#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advertise a Linux host (PC, Raspberry Pi, VM) as a Cisco CDP neighbor.

Sends 802.3/LLC/SNAP CDP frames through AF_PACKET, so a Cisco switch lists
this machine in ``show cdp neighbors``.

No Npcap, no libpcap, no third-party Python package: only the Python standard
library plus CAP_NET_RAW (root, or an explicit setcap).  This is the
recommended replacement for the Windows version on machines where endpoint
protection (ESET HIPS) blocks pcap-based raw-frame injection, because nothing
is installed and no packet driver is involved.

Use it only on networks you own or are allowed to test on.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:  # Linux-only; the packet builder still works without it (for --selftest)
    import fcntl
except ImportError:  # pragma: no cover - Windows/macOS
    fcntl = None  # type: ignore[assignment]

APP_NAME = "CdpNeighbor (AF_PACKET)"
DEFAULT_VERSION = (
    "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
    "Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)"
)

# CDP is sent to the Cisco multicast MAC with an 802.3 LLC/SNAP header.
CDP_DST_MAC = bytes.fromhex("01000ccccccc")
CDP_LLC_SNAP = b"\xaa\xaa\x03" + b"\x00\x00\x0c" + b"\x20\x00"
SNAP_PID_CDP = 0x2000

# CDP TLV types.
TLV_DEVICE_ID = 0x0001
TLV_ADDRESSES = 0x0002
TLV_PORT_ID = 0x0003
TLV_CAPABILITIES = 0x0004
TLV_VERSION = 0x0005
TLV_PLATFORM = 0x0006
TLV_VTP_DOMAIN = 0x0009
TLV_NATIVE_VLAN = 0x000A
TLV_DUPLEX = 0x000B

# CDP capability bits.
CAPABILITIES = {
    "router": 0x01,
    "transparent-bridge": 0x02,
    "source-route-bridge": 0x04,
    "switch": 0x08,
    "host": 0x10,
    "igmp": 0x20,
    "repeater": 0x40,
}
CAPABILITY_LETTERS = {
    0x01: "R", 0x02: "T", 0x04: "B", 0x08: "S",
    0x10: "H", 0x20: "I", 0x40: "r",
}

# ioctl numbers are identical on every Linux architecture.
SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927
IFF_UP = 0x1
IFREQ_SIZE = 40  # 16-byte name + 16-byte union, padded for safety

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")

# Frame produced by the verified Windows implementation for the demo
# parameters in --selftest.  The Linux builder must reproduce it byte for byte.
REFERENCE_FRAME_HEX = (
    "01000cccccccaabbccddeeff00dd"
    "aaaa0300000c2000"
    "02b46799000100104344502d53454c4654455354"
    "00020011000000010101cc0004c000020a"
    "000300164769676162697445746865726e6574302f31"
    "0004000800000028"
    "00050067436973636f20494f5320536f6674776172652c20433239363020536f6674"
    "77617265202843323936302d4c414e424153454b392d4d292c2056657273696f6e20"
    "31352e30283229534531312c2052454c4541534520534f4654574152452028666333"
    "29"
    "00060019636973636f2057532d43323936302d323454542d4c"
    "000900074c4142"
    "000a0006000a"
    "000b000501"
)


# ---------------------------------------------------------------------------
# CDP packet builder (identical logic to the Windows version)
# ---------------------------------------------------------------------------
def checksum(data: bytes) -> int:
    """Cisco CDP 16-bit one's complement checksum.

    CDP differs from the IP checksum for odd-length payloads: Cisco inserts
    the pad byte *before* the final byte, so the last byte becomes the low
    byte of the last 16-bit word.  Verified against real CDP frames sent by a
    Cisco C2960S switch.
    """
    if len(data) % 2:
        data = data[:-1] + b"\x00" + data[-1:]
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", tlv_type, len(value) + 4) + value


def build_cdp_payload(
    *,
    hostname: str,
    port_id: str,
    platform: str = "cisco WS-C2960-24TT-L",
    version_string: str = DEFAULT_VERSION,
    capabilities: int = CAPABILITIES["switch"] | CAPABILITIES["igmp"],
    ip: Optional[str] = None,
    vlan: Optional[int] = None,
    vtp_domain: Optional[str] = None,
    ttl: int = 180,
    full_duplex: bool = True,
) -> bytes:
    """Build the CDP part (header + TLVs) of the frame."""
    tlvs = bytearray()
    tlvs += _tlv(TLV_DEVICE_ID, hostname.encode("utf-8", "replace"))

    if ip:
        packed_ip = socket.inet_aton(ip)
        address = (
            struct.pack("!I", 1)
            + b"\x01\x01\xcc"
            + struct.pack("!H", len(packed_ip))
            + packed_ip
        )
        tlvs += _tlv(TLV_ADDRESSES, address)

    tlvs += _tlv(TLV_PORT_ID, port_id.encode("utf-8", "replace"))
    tlvs += _tlv(TLV_CAPABILITIES, struct.pack("!I", capabilities & 0xFFFFFFFF))
    tlvs += _tlv(TLV_VERSION, version_string.encode("utf-8", "replace"))
    tlvs += _tlv(TLV_PLATFORM, platform.encode("utf-8", "replace"))
    if vtp_domain is not None:
        tlvs += _tlv(TLV_VTP_DOMAIN, vtp_domain.encode("utf-8", "replace"))
    if vlan is not None:
        tlvs += _tlv(TLV_NATIVE_VLAN, struct.pack("!H", vlan))
    tlvs += _tlv(TLV_DUPLEX, b"\x01" if full_duplex else b"\x00")

    version = 2
    body = struct.pack("!BBH", version, ttl, 0) + bytes(tlvs)
    cksum = checksum(body)
    return struct.pack("!BBH", version, ttl, cksum) + bytes(tlvs)


def build_frame(src_mac: bytes, cdp_payload: bytes) -> bytes:
    """Wrap the CDP payload in an Ethernet 802.3 + LLC/SNAP frame."""
    if len(src_mac) != 6:
        raise ValueError("source MAC must be 6 bytes")
    payload = CDP_LLC_SNAP + cdp_payload
    length = len(payload)
    if len(payload) < 46:  # Ethernet minimum payload, FCS excluded
        payload += b"\x00" * (46 - len(payload))
    return CDP_DST_MAC + src_mac + struct.pack("!H", length) + payload


def parse_mac(text: str) -> bytes:
    if not _MAC_RE.match(text):
        raise argparse.ArgumentTypeError(
            "invalid MAC address (expected AA:BB:CC:DD:EE:FF)"
        )
    return bytes.fromhex(text.replace(":", "").replace("-", ""))


def format_mac(mac: Optional[bytes]) -> str:
    if not mac:
        return "-"
    return ":".join(f"{b:02X}" for b in mac)


def parse_capabilities(text: str) -> int:
    value = 0
    for part in re.split(r"[,\s+]+", text.strip()):
        if not part:
            continue
        key = part.lower()
        if key in CAPABILITIES:
            value |= CAPABILITIES[key]
            continue
        try:
            value |= int(part, 0)
        except ValueError:
            allowed = ", ".join(CAPABILITIES)
            raise argparse.ArgumentTypeError(
                f"unknown capability {part!r}; use {allowed} or a number"
            )
    return value


def capabilities_text(value: int) -> str:
    names = [name for name, bit in CAPABILITIES.items() if value & bit]
    letters = "".join(
        letter for bit, letter in CAPABILITY_LETTERS.items() if value & bit
    )
    if names:
        return f"0x{value:02X} ({'+'.join(names)} / {letters or '-'})"
    return f"0x{value:02X}"


# ---------------------------------------------------------------------------
# Interface discovery (ioctl / sysfs, no external commands)
# ---------------------------------------------------------------------------
@dataclass
class Iface:
    name: str
    index: int
    mac: Optional[bytes]
    ipv4: Optional[str]
    up: bool


def _ioctl(sock: socket.socket, request: int, name: str) -> bytes:
    request_buffer = name.encode("utf-8")[:15].ljust(16, b"\x00")
    request_buffer += b"\x00" * (IFREQ_SIZE - 16)
    return fcntl.ioctl(sock.fileno(), request, request_buffer)


def _mac_from_sysfs(name: str) -> Optional[bytes]:
    try:
        with open(f"/sys/class/net/{name}/address", "r", encoding="ascii") as handle:
            text = handle.read().strip()
    except OSError:
        return None
    if not _MAC_RE.match(text):
        return None
    return bytes.fromhex(text.replace(":", ""))


def _mac_from_ioctl(sock: socket.socket, name: str) -> Optional[bytes]:
    try:
        result = _ioctl(sock, SIOCGIFHWADDR, name)
    except OSError:
        return None
    return bytes(result[18:24])


def _ipv4_from_ioctl(sock: socket.socket, name: str) -> Optional[str]:
    try:
        result = _ioctl(sock, SIOCGIFADDR, name)
    except OSError:
        return None
    packed = bytes(result[20:24])
    if packed == b"\x00\x00\x00\x00":
        return None
    return socket.inet_ntoa(packed)


def _is_up(sock: socket.socket, name: str) -> bool:
    try:
        flags = struct.unpack_from("H", _ioctl(sock, SIOCGIFFLAGS, name), 16)[0]
    except OSError:
        return False
    return bool(flags & IFF_UP)


def discover_interfaces() -> List[Iface]:
    if fcntl is None:
        raise RuntimeError("Interface discovery requires Linux.")
    interfaces: List[Iface] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        for index, name in socket.if_nameindex():
            if name == "lo":
                continue
            interfaces.append(
                Iface(
                    name=name,
                    index=index,
                    mac=_mac_from_sysfs(name) or _mac_from_ioctl(control, name),
                    ipv4=_ipv4_from_ioctl(control, name),
                    up=_is_up(control, name),
                )
            )
    interfaces.sort(key=lambda item: (not item.up, item.index))
    return interfaces


def print_interfaces(interfaces: List[Iface]) -> None:
    print("Available network interfaces:")
    print()
    print(f"  {'#':<3} {'Name':<16} {'IPv4':<16} {'MAC':<18} State")
    print(f"  {'-' * 3} {'-' * 16} {'-' * 16} {'-' * 18} {'-' * 12}")
    for index, iface in enumerate(interfaces, 1):
        state = "up" if iface.up else "down"
        print(
            f"  {index:<3} {iface.name[:16]:<16} "
            f"{(iface.ipv4 or '-'):<16} {format_mac(iface.mac):<18} {state}"
        )
    print()


def match_interface(interfaces: List[Iface], selector: str) -> Iface:
    selector = selector.strip()
    if selector.isdigit():
        index = int(selector)
        if 1 <= index <= len(interfaces):
            return interfaces[index - 1]
        raise LookupError(f"There is no interface number {index}.")
    exact = [item for item in interfaces if item.name == selector]
    if exact:
        return exact[0]
    partial = [item for item in interfaces if selector.lower() in item.name.lower()]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise LookupError(f"No interface matches {selector!r}.")
    choices = ", ".join(f"{index + 1}={item.name}" for index, item in enumerate(interfaces))
    raise LookupError(f"Ambiguous interface name; use a number: {choices}")


def pick_interface(
    interfaces: List[Iface], selector: Optional[str]
) -> Iface:
    if selector:
        return match_interface(interfaces, selector)
    candidates = [item for item in interfaces if item.up and item.mac]
    if len(candidates) == 1:
        print(f"Auto-selected the only usable interface: {candidates[0].name}")
        return candidates[0]
    if not sys.stdin.isatty():
        raise LookupError(
            "No interface selected. Use --iface NAME (or --list to see them)."
        )
    print_interfaces(interfaces)
    while True:
        try:
            answer = input("Select interface number (or part of its name) [1]: ")
        except EOFError:
            raise LookupError("No interface selected.")
        answer = answer.strip() or "1"
        try:
            return match_interface(interfaces, answer)
        except LookupError as exc:
            print(f"  {exc}")


# ---------------------------------------------------------------------------
# AF_PACKET sender
# ---------------------------------------------------------------------------
def open_sender(interface: Iface) -> socket.socket:
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError(
            "This script needs Linux with AF_PACKET. On Windows use "
            "cdp_advertiser.py instead."
        )
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind((interface.name, 0))  # protocol 0 -> we never receive frames
    except OSError as exc:
        sock.close()
        raise RuntimeError(_explain_send_error(exc, interface)) from exc
    return sock


def _explain_send_error(exc: OSError, interface: Iface) -> str:
    if exc.errno == 1:  # EPERM
        return (
            f"Permission denied on {interface.name}. AF_PACKET needs CAP_NET_RAW: "
            "run with sudo (or 'sudo setcap cap_net_raw+ep $(readlink -f "
            "$(command -v python3))' once)."
        )
    if exc.errno == 19:  # ENODEV
        return f"Interface {interface.name!r} disappeared. Check '--list'."
    if exc.errno == 100:  # ENETDOWN
        return (
            f"Interface {interface.name!r} is down. Bring it up first:\n"
            f"  sudo ip link set {interface.name} up"
        )
    return f"Cannot open {interface.name!r}: {exc.strerror or exc}"


def send_frame(sock: socket.socket, interface: Iface, frame: bytes) -> None:
    try:
        sock.sendto(frame, (interface.name, 0))
    except OSError as exc:
        raise RuntimeError(_explain_send_error(exc, interface)) from exc


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def selftest() -> int:
    print("1) CDP checksum")
    payload = build_cdp_payload(
        hostname="CDP-SELFTEST",
        port_id="GigabitEthernet0/1",
        platform="cisco WS-C2960-24TT-L",
        version_string=DEFAULT_VERSION,
        capabilities=CAPABILITIES["switch"] | CAPABILITIES["igmp"],
        ip="192.0.2.10",
        vlan=10,
        vtp_domain="LAB",
        ttl=180,
        full_duplex=True,
    )
    total = checksum(payload)
    if total != 0:
        print(f"   FAIL: checksum should validate to 0, got 0x{total:04X}")
        return 1
    print(f"   version 2, TTL 180, {len(payload)} bytes, checksum OK")

    print("2) Frame matches the verified reference")
    frame = build_frame(bytes.fromhex("AABBCCDDEEFF"), payload)
    expected = bytes.fromhex(REFERENCE_FRAME_HEX)
    if frame != expected:
        print(f"   FAIL: frame differs ({len(frame)} vs {len(expected)} bytes)")
        for offset, (got, want) in enumerate(zip(frame, expected)):
            if got != want:
                print(f"   first difference at offset {offset}: "
                      f"0x{got:02x} != 0x{want:02x}")
                break
        return 1
    print(f"   identical, {len(frame)} bytes, destination 01:00:0C:CC:CC:CC")

    print()
    print("Self-test passed.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cdp_advertiser_linux.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Send CDP frames from a Linux host so a Cisco switch shows it in "
            "'show cdp neighbors'. Uses AF_PACKET: no Npcap, no libpcap, no "
            "extra packages."
        ),
        epilog=(
            "examples:\n"
            "  sudo python3 cdp_advertiser_linux.py --list\n"
            "  sudo python3 cdp_advertiser_linux.py --iface eth0\n"
            "  sudo python3 cdp_advertiser_linux.py --iface eth0 --hostname LAB-SW2\n"
            "  sudo python3 cdp_advertiser_linux.py --iface eth0 --dry-run\n"
            "  python3 cdp_advertiser_linux.py --selftest\n"
        ),
    )
    parser.add_argument("--list", action="store_true", help="list interfaces and exit")
    parser.add_argument("--selftest", action="store_true",
                        help="verify the packet builder, send nothing")
    parser.add_argument("-i", "--iface", metavar="NAME",
                        help="interface name or number from --list")
    parser.add_argument("--hostname", default=socket.gethostname(),
                        help="CDP Device ID (default: this host's name)")
    parser.add_argument("--platform", default="cisco WS-C2960-24TT-L",
                        help="CDP Platform string (default: %(default)s)")
    parser.add_argument("--port", default="GigabitEthernet0/1", dest="port_id",
                        help="CDP Port ID advertised to the switch (default: %(default)s)")
    parser.add_argument("--version-string", default=DEFAULT_VERSION, metavar="TEXT",
                        help="CDP software version text")
    parser.add_argument("--capabilities", type=parse_capabilities,
                        default=CAPABILITIES["switch"] | CAPABILITIES["igmp"],
                        metavar="LIST",
                        help="comma list: router, switch, host, igmp, repeater, "
                             "transparent-bridge, source-route-bridge, or a number "
                             "(default: switch,igmp)")
    parser.add_argument("--ip", metavar="ADDR",
                        help="IPv4 address to advertise (default: auto-detect)")
    parser.add_argument("--no-address", action="store_true",
                        help="do not send the Address TLV at all")
    parser.add_argument("--mac", type=parse_mac, metavar="AA:BB:CC:DD:EE:FF",
                        help="source MAC to put in the frames (default: interface MAC)")
    parser.add_argument("--vlan", type=int, metavar="N",
                        help="also advertise this native VLAN (omitted by default)")
    parser.add_argument("--vtp-domain", metavar="NAME",
                        help="optional VTP management domain string")
    parser.add_argument("--ttl", type=int, default=180, metavar="SEC",
                        help="CDP holdtime in seconds, 1-255 (default: %(default)s)")
    parser.add_argument("--interval", type=float, default=60.0, metavar="SEC",
                        help="seconds between advertisements (default: %(default)s)")
    parser.add_argument("--count", type=int, default=0, metavar="N",
                        help="stop after N frames (default: 0 = run until Ctrl+C)")
    parser.add_argument("--half-duplex", action="store_true",
                        help="advertise half duplex (default: full)")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and print the frame, do not send anything")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print the hex dump of every frame")
    return parser


def validate_args(parser: argparse.ArgumentParser, args) -> None:
    if not 1 <= args.ttl <= 255:
        parser.error("--ttl must be between 1 and 255")
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    if args.count < 0:
        parser.error("--count cannot be negative")
    if args.vlan is not None and not 1 <= args.vlan <= 4094:
        parser.error("--vlan must be between 1 and 4094")
    if args.vtp_domain and len(args.vtp_domain.encode("utf-8", "replace")) > 255:
        parser.error("--vtp-domain is too long (max 255 bytes)")
    if args.ip:
        try:
            socket.inet_aton(args.ip)
        except OSError:
            parser.error(f"invalid IPv4 address: {args.ip}")
    for flag, attribute in (
        ("--hostname", "hostname"),
        ("--platform", "platform"),
        ("--port", "port_id"),
        ("--version-string", "version_string"),
    ):
        if len(getattr(args, attribute).encode("utf-8", "replace")) > 255:
            parser.error(f"{flag} is too long (max 255 bytes)")


def print_hex(frame: bytes) -> None:
    for offset in range(0, len(frame), 16):
        chunk = frame[offset:offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        text_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        print(f"  {offset:04x}  {hex_part:<47}  {text_part}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)

    if args.selftest:
        return selftest()

    try:
        interfaces = discover_interfaces()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: cannot enumerate interfaces: {exc}", file=sys.stderr)
        return 2

    if args.list:
        print_interfaces(interfaces)
        return 0

    if not interfaces:
        print("ERROR: no network interfaces found.", file=sys.stderr)
        return 2

    try:
        interface = pick_interface(interfaces, args.iface)
    except LookupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    source_mac = args.mac or interface.mac
    if not source_mac:
        print(
            "ERROR: could not read the MAC address of the selected interface.\n"
            "Pass it explicitly, for example --mac A4:BB:6D:11:22:33",
            file=sys.stderr,
        )
        return 2

    advertised_ip = None if args.no_address else (args.ip or interface.ipv4)

    cdp_payload = build_cdp_payload(
        hostname=args.hostname,
        port_id=args.port_id,
        platform=args.platform,
        version_string=args.version_string,
        capabilities=args.capabilities,
        ip=advertised_ip,
        vlan=args.vlan,
        vtp_domain=args.vtp_domain,
        ttl=args.ttl,
        full_duplex=not args.half_duplex,
    )
    frame = build_frame(source_mac, cdp_payload)

    print(f"{APP_NAME} - CDP neighbor advertiser")
    print(f"  Interface   : {interface.name} (up={interface.up})")
    print(f"  Source MAC  : {format_mac(source_mac)}")
    print(f"  Device ID   : {args.hostname}")
    print(f"  Platform    : {args.platform}")
    print(f"  Port ID     : {args.port_id}")
    print(f"  IP address  : {advertised_ip or '(not advertised)'}")
    print(f"  VLAN        : {args.vlan if args.vlan is not None else '(not advertised)'}")
    print(f"  Capabilities: {capabilities_text(args.capabilities)}")
    print(f"  Holdtime    : {args.ttl}s")
    print(f"  Frame size  : {len(frame)} bytes")
    if args.interval >= args.ttl and not args.count:
        print(
            "  WARNING     : interval >= TTL; the neighbor will time out "
            "between advertisements."
        )
    print()

    if args.dry_run:
        print("Dry run - frame that would be sent:")
        print_hex(frame)
        return 0

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "ERROR: AF_PACKET requires root (CAP_NET_RAW).\n"
            "       Re-run with sudo, or grant the capability to python3 once.",
            file=sys.stderr,
        )
        return 2

    if not interface.up:
        print(
            f"WARNING: {interface.name} is reported as down; bring it up with "
            f"'sudo ip link set {interface.name} up'.",
            file=sys.stderr,
        )

    sock = None
    sent = 0
    try:
        sock = open_sender(interface)
        print(
            f"Sending to {format_mac(CDP_DST_MAC)} every {args.interval:g}s. "
            "Press Ctrl+C to stop."
        )
        while True:
            send_frame(sock, interface, frame)
            sent += 1
            print(
                f"[{time.strftime('%H:%M:%S')}] sent #{sent} ({len(frame)} bytes)",
                flush=True,
            )
            if args.verbose:
                print_hex(frame)
            if args.count and sent >= args.count:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
        print("Stopped by user.")
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if sock:
            sock.close()

    if sent:
        print(
            f"Sent {sent} advertisement(s). The switch drops the neighbor "
            f"about {args.ttl}s after the last one."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
