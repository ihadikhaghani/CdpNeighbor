#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Self-test for CdpNeighbor.

Default run (no Npcap needed):
    python selftest.py
    builds a sample CDP frame and validates its structure and checksum.

Against the real network (Npcap needed):
    python selftest.py --listen 70
        passively captures CDP frames from Cisco devices and verifies the
        checksum routine against real hardware.

    python selftest.py --send
        transmits one advertisement frame (use when you are ready to look at
        the switch's "show cdp neighbors" output).
"""

from __future__ import annotations

import argparse
import ctypes
import struct
import sys
import time
from typing import List, Optional, Tuple

import cdp_advertiser as m


class PcapPkthdr(ctypes.Structure):
    _fields_ = [
        ("ts_sec", ctypes.c_long),
        ("ts_usec", ctypes.c_long),
        ("caplen", ctypes.c_uint),
        ("len", ctypes.c_uint),
    ]


def parse_cdp(payload: bytes) -> Tuple[int, int, int, List[Tuple[int, bytes]]]:
    if len(payload) < 4:
        raise ValueError("CDP payload shorter than its 4-byte header")
    version, ttl, stored = struct.unpack("!BBH", payload[:4])
    tlvs: List[Tuple[int, bytes]] = []
    position = 4
    while position < len(payload):
        if position + 4 > len(payload):
            raise ValueError(f"truncated TLV header at offset {position}")
        tlv_type, length = struct.unpack("!HH", payload[position:position + 4])
        if length < 4 or position + length > len(payload):
            raise ValueError(
                f"bad TLV length {length} for type 0x{tlv_type:04x} "
                f"at offset {position}"
            )
        tlvs.append((tlv_type, payload[position + 4:position + length]))
        position += length
    return version, ttl, stored, tlvs


def extract_cdp(frame: bytes) -> Optional[bytes]:
    if len(frame) < 22:
        return None
    if frame[:6] != m.CDP_DST_MAC:
        return None
    if frame[14:17] != b"\xaa\xaa\x03":
        return None
    if frame[17:22] != b"\x00\x00\x0c\x20\x00":
        return None
    length = struct.unpack("!H", frame[12:14])[0]
    end = 14 + length
    if end < 22 or end > len(frame):
        return None
    return frame[22:end]


def make_demo_payload() -> bytes:
    return m.build_cdp_payload(
        hostname="CDP-SELFTEST",
        port_id="GigabitEthernet0/1",
        platform="cisco WS-C2960-24TT-L",
        version_string=m.DEFAULT_VERSION,
        capabilities=m.CAPABILITIES["switch"] | m.CAPABILITIES["igmp"],
        ip="192.0.2.10",
        vlan=10,
        vtp_domain="LAB",
        ttl=180,
        full_duplex=True,
    )


def offline_checks() -> bytes:
    print("1) CDP payload")
    payload = make_demo_payload()
    version, ttl, stored, tlvs = parse_cdp(payload)
    assert version == 2, f"expected CDP version 2, got {version}"
    assert ttl == 180, f"expected TTL 180, got {ttl}"
    print(f"   version 2, TTL {ttl}, checksum 0x{stored:04X}, "
          f"{len(payload)} bytes, {len(tlvs)} TLVs")

    by_type = {tlv_type: value for tlv_type, value in tlvs}
    required = {
        m.TLV_DEVICE_ID: "device ID",
        m.TLV_ADDRESSES: "addresses",
        m.TLV_PORT_ID: "port ID",
        m.TLV_CAPABILITIES: "capabilities",
        m.TLV_VERSION: "software version",
        m.TLV_PLATFORM: "platform",
        m.TLV_VTP_DOMAIN: "VTP domain",
        m.TLV_NATIVE_VLAN: "native VLAN",
        m.TLV_DUPLEX: "duplex",
    }
    for tlv_type, name in required.items():
        assert tlv_type in by_type, f"missing {name} TLV"
        print(f"   0x{tlv_type:04x} {name:<16} {by_type[tlv_type]!r}")

    assert by_type[m.TLV_DEVICE_ID] == b"CDP-SELFTEST"
    assert by_type[m.TLV_PORT_ID] == b"GigabitEthernet0/1"
    expected_address = (
        b"\x00\x00\x00\x01\x01\x01\xcc\x00\x04" + bytes([192, 0, 2, 10])
    )
    assert by_type[m.TLV_ADDRESSES] == expected_address
    assert by_type[m.TLV_NATIVE_VLAN] == b"\x00\x0a"
    assert struct.unpack("!I", by_type[m.TLV_CAPABILITIES])[0] == 0x28
    assert by_type[m.TLV_DUPLEX] == b"\x01"

    print("2) CDP checksum")
    assert m.checksum(payload) == 0, (
        f"checksum did not validate (got 0x{m.checksum(payload):04X})"
    )
    print("   full-payload check returns 0 -> valid")

    print("3) Ethernet frame")
    source_mac = bytes.fromhex("AABBCCDDEEFF")
    frame = m.build_frame(source_mac, payload)
    assert frame[:6] == m.CDP_DST_MAC
    assert frame[6:12] == source_mac
    length = struct.unpack("!H", frame[12:14])[0]
    assert length == len(payload) + len(m.CDP_LLC_SNAP)
    assert frame[14:22] == m.CDP_LLC_SNAP
    assert frame[22:22 + len(payload)] == payload
    assert len(frame) == 14 + length
    print(f"   destination 01:00:0C:CC:CC:CC, {len(frame)} bytes, "
          f"802.3 length {length}")

    print()
    print("Offline checks passed.")
    print()
    return frame


def enable_capture(lib) -> None:
    lib.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(PcapPkthdr)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ]
    lib.pcap_next_ex.restype = ctypes.c_int


def read_packet(lib, handle):
    header = ctypes.POINTER(PcapPkthdr)()
    data = ctypes.POINTER(ctypes.c_ubyte)()
    rc = lib.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(data))
    if rc == 1:
        return bytes(data[:header.contents.caplen])
    return None


def describe_cdp(cdp: bytes) -> None:
    version, ttl, _, tlvs = parse_cdp(cdp)
    fields = {tlv_type: value for tlv_type, value in tlvs}
    valid = m.checksum(cdp) == 0

    def text(tlv_type: int) -> str:
        value = fields.get(tlv_type)
        return value.decode("utf-8", "replace") if value is not None else "-"

    print(f"   CDP v{version}  TTL {ttl}  {len(cdp)} bytes  "
          f"checksum {'OK' if valid else 'BAD'}")
    print(f"   Device ID : {text(m.TLV_DEVICE_ID)}")
    print(f"   Port ID   : {text(m.TLV_PORT_ID)}")
    print(f"   Platform  : {text(m.TLV_PLATFORM)}")


def listen(lib, adapter, seconds: float) -> int:
    enable_capture(lib)
    handle = m.open_adapter(lib, adapter, promiscuous=True)
    print(f"Listening for CDP frames on {adapter.friendly} for {seconds:g}s ...")
    found = 0
    bad = 0
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            frame = read_packet(lib, handle)
            if frame is None:
                continue
            cdp = extract_cdp(frame)
            if cdp is None:
                continue
            found += 1
            print(f"\n[{time.strftime('%H:%M:%S')}] CDP frame from "
                  f"{m.format_mac(frame[6:12])}")
            describe_cdp(cdp)
            if m.checksum(cdp) != 0:
                bad += 1
    finally:
        lib.pcap_close(handle)
    print(f"\nCaptured {found} CDP frame(s), {bad} with a bad checksum.")
    return 0 if found and not bad else (0 if not found else 1)


def send_one(lib, adapter, frame: bytes) -> int:
    enable_capture(lib)
    handle = m.open_adapter(lib, adapter, promiscuous=True)
    try:
        print(f"Sending one CDP frame on {adapter.friendly} ...")
        m.send_frame(lib, handle, frame)
        print("   sent")
        deadline = time.time() + 2.0
        while time.time() < deadline:
            captured = read_packet(lib, handle)
            if captured is None:
                continue
            if captured[:len(frame)] == frame:
                print("   captured the same frame back from the adapter")
                return 0
        print("   frame was sent, but this driver did not show it in capture "
              "(not an error)")
        return 0
    finally:
        lib.pcap_close(handle)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline and live self-tests for CdpNeighbor."
    )
    parser.add_argument(
        "-i", "--iface", help="adapter name, description, or number"
    )
    parser.add_argument(
        "--listen", type=float, metavar="SECONDS",
        help="passively capture real CDP frames and verify their checksums",
    )
    parser.add_argument(
        "--send", action="store_true",
        help="send one advertisement frame (visible to the switch)",
    )
    args = parser.parse_args(argv)

    frame = offline_checks()

    if not args.listen and not args.send:
        print("Nothing was sent. Use --listen SECONDS or --send to test the "
              "network side.")
        return 0

    try:
        lib = m.load_wpcap()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        adapters = m.discover_adapters(lib)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not adapters:
        print("ERROR: no capture adapters found (is Npcap installed?)",
              file=sys.stderr)
        return 2

    m.print_adapters(adapters)
    try:
        adapter = m.pick_adapter(adapters, args.iface)
    except LookupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Using adapter: {adapter.friendly} [{m.format_mac(adapter.mac)}]")
    print()

    try:
        if args.listen:
            return listen(lib, adapter, args.listen)
        source_mac = adapter.mac
        if not source_mac:
            print("ERROR: adapter MAC unknown; choose another adapter.",
                  file=sys.stderr)
            return 2
        return send_one(lib, adapter, m.build_frame(source_mac, make_demo_payload()))
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
