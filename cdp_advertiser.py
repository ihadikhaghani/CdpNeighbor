#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advertise this Windows machine as a Cisco CDP neighbor.

The program builds 802.3/LLC/SNAP CDP frames and sends them through a
selected network adapter, so a Cisco switch lists this machine in
``show cdp neighbors``.

Nothing is installed and nothing is reconfigured: only raw Ethernet frames
are transmitted.  Npcap (WinPcap API) must be installed; it is called
directly through ctypes, so no third-party Python package is required.

Use it only on networks you own or are allowed to test on.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import re
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

APP_NAME = "CdpNeighbor"
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

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
_GUID_RE = re.compile(r"\{[0-9a-fA-F-]{36}\}")
_DLL_DIRS: List[object] = []


# ---------------------------------------------------------------------------
# CDP packet builder
# ---------------------------------------------------------------------------
def checksum(data: bytes) -> int:
    """Cisco CDP 16-bit one's complement checksum.

    CDP differs from the IP checksum for odd-length payloads: Cisco inserts
    the pad byte *before* the final byte, so the last byte becomes the low
    byte of the last 16-bit word.  This was verified against real CDP frames
    sent by a Cisco C2960S switch.  The builder always ends with the Duplex
    TLV (value 0x00/0x01), so the final byte is always a small value.
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
        # Address TLV: one address, protocol type NLPID, protocol 0xCC (IPv4).
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

    # CDP header: version, TTL, checksum (checksum is computed with 0 first).
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
# Npcap (wpcap.dll) bindings
# ---------------------------------------------------------------------------
class _SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


class _PcapAddr(ctypes.Structure):
    pass


_PcapAddr._fields_ = [
    ("next", ctypes.POINTER(_PcapAddr)),
    ("addr", ctypes.POINTER(_SockaddrIn)),
    ("netmask", ctypes.POINTER(_SockaddrIn)),
    ("broadaddr", ctypes.POINTER(_SockaddrIn)),
    ("dstaddr", ctypes.POINTER(_SockaddrIn)),
]


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", ctypes.POINTER(_PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(_PcapAddr)),
    ("flags", ctypes.c_uint),
]


class _IPAdapterAddresses(ctypes.Structure):
    pass


_IPAdapterAddresses._fields_ = [
    ("Length", ctypes.c_ulong),
    ("IfIndex", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_IPAdapterAddresses)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.c_void_p),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", ctypes.c_ulong),
]


def load_wpcap():
    """Load wpcap.dll, also looking in the Npcap installation folder."""
    if os.name != "nt":
        raise RuntimeError("This tool only runs on Windows.")
    candidates: List[str] = []
    for folder in (r"C:\Windows\System32\Npcap", r"C:\Windows\SysWOW64\Npcap"):
        if os.path.isdir(folder):
            try:
                _DLL_DIRS.append(os.add_dll_directory(folder))
            except (AttributeError, OSError):
                pass
            candidates.append(os.path.join(folder, "wpcap.dll"))
    candidates += [
        "wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",
        r"C:\Windows\SysWOW64\wpcap.dll",
    ]
    last_error = None
    for candidate in candidates:
        try:
            lib = ctypes.WinDLL(candidate)
            _setup_pcap(lib)
            return lib
        except OSError as exc:
            last_error = exc
    raise RuntimeError(
        "wpcap.dll (Npcap) was not found. Install Npcap from "
        "https://npcap.com/#download and run this program again. "
        f"({last_error})"
    )


def _setup_pcap(lib) -> None:
    lib.pcap_findalldevs.argtypes = [
        ctypes.POINTER(ctypes.POINTER(_PcapIf)),
        ctypes.c_char_p,
    ]
    lib.pcap_findalldevs.restype = ctypes.c_int
    lib.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
    lib.pcap_freealldevs.restype = None
    lib.pcap_open_live.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p
    ]
    lib.pcap_open_live.restype = ctypes.c_void_p
    lib.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.pcap_sendpacket.restype = ctypes.c_int
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    lib.pcap_geterr.restype = ctypes.c_char_p
    lib.pcap_close.argtypes = [ctypes.c_void_p]
    lib.pcap_close.restype = None


@dataclass
class Adapter:
    name: str
    description: str
    friendly: str
    mac: Optional[bytes]
    ipv4: Optional[str]


def _decode(value: Optional[bytes]) -> str:
    return (value or b"").decode("utf-8", "replace")


def _guid_from_pcap_name(name: str) -> Optional[str]:
    match = _GUID_RE.search(name)
    return match.group(0).lower() if match else None


def _windows_adapter_info() -> Dict[str, Dict[str, object]]:
    """Map adapter GUID -> {friendly, description, mac} via iphlpapi."""
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi.dll")
    except OSError:
        return {}

    iphlpapi.GetAdaptersAddresses.argtypes = [
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.POINTER(_IPAdapterAddresses),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    iphlpapi.GetAdaptersAddresses.restype = ctypes.c_ulong

    size = ctypes.c_ulong(0)
    rc = iphlpapi.GetAdaptersAddresses(0, 0, None, None, ctypes.byref(size))
    if rc not in (0, 111):  # 111 = ERROR_BUFFER_OVERFLOW
        return {}
    buffer = ctypes.create_string_buffer(max(size.value, 1))
    head = ctypes.cast(buffer, ctypes.POINTER(_IPAdapterAddresses))
    rc = iphlpapi.GetAdaptersAddresses(0, 0, None, head, ctypes.byref(size))
    if rc != 0:
        return {}

    result: Dict[str, Dict[str, object]] = {}
    node = head
    while node:
        item = node.contents
        guid = (item.AdapterName or b"").decode("ascii", "replace").lower()
        length = min(int(item.PhysicalAddressLength), 8)
        mac = bytes(item.PhysicalAddress[:length]) if length == 6 else None
        result[guid] = {
            "friendly": item.FriendlyName or "",
            "description": item.Description or "",
            "mac": mac,
        }
        node = item.Next
    return result


def _pcap_devices(lib) -> List[Dict[str, object]]:
    devices: List[Dict[str, object]] = []
    error_buffer = ctypes.create_string_buffer(256)
    alldevs = ctypes.POINTER(_PcapIf)()
    if lib.pcap_findalldevs(ctypes.byref(alldevs), error_buffer) != 0:
        raise RuntimeError(
            _decode(error_buffer.value) or "pcap_findalldevs failed"
        )
    try:
        node = alldevs
        while node:
            dev = node.contents
            ipv4_addresses: List[str] = []
            addr = dev.addresses
            while addr:
                entry = addr.contents
                if entry.addr:
                    sockaddr = entry.addr.contents
                    if sockaddr.sin_family == socket.AF_INET:
                        ipv4_addresses.append(
                            socket.inet_ntoa(bytes(sockaddr.sin_addr))
                        )
                addr = entry.next
            devices.append(
                {
                    "name": _decode(dev.name),
                    "description": _decode(dev.description),
                    "ipv4": ipv4_addresses,
                }
            )
            node = dev.next
    finally:
        lib.pcap_freealldevs(alldevs)
    return devices


def discover_adapters(lib) -> List[Adapter]:
    windows_info = _windows_adapter_info()
    adapters: List[Adapter] = []
    for device in _pcap_devices(lib):
        name = str(device["name"])
        description = str(device["description"])
        guid = _guid_from_pcap_name(name)
        info = windows_info.get(guid or "", {})
        friendly = str(info.get("friendly") or "")
        if not friendly:
            friendly = description or f"adapter{len(adapters) + 1}"
        ips = [ip for ip in device["ipv4"] if ip and ip != "0.0.0.0"]
        preferred = [ip for ip in ips if not ip.startswith("169.254.")]
        adapters.append(
            Adapter(
                name=name,
                description=description or friendly,
                friendly=friendly,
                mac=info.get("mac") if isinstance(info.get("mac"), bytes) else None,
                ipv4=(preferred or ips or [None])[0],
            )
        )
    return adapters


def print_adapters(adapters: List[Adapter]) -> None:
    print("Available network adapters:")
    print()
    print(
        f"  {'#':<3} {'Name':<20} {'IPv4':<16} {'MAC':<18} Description"
    )
    print(f"  {'-' * 3} {'-' * 20} {'-' * 16} {'-' * 18} {'-' * 34}")
    for index, adapter in enumerate(adapters, 1):
        print(
            f"  {index:<3} {adapter.friendly[:20]:<20} "
            f"{(adapter.ipv4 or '-'):<16} "
            f"{format_mac(adapter.mac):<18} {adapter.description}"
        )
    print()


def match_adapter(adapters: List[Adapter], selector: str) -> Adapter:
    selector = selector.strip()
    if selector.isdigit():
        index = int(selector)
        if 1 <= index <= len(adapters):
            return adapters[index - 1]
        raise LookupError(f"There is no adapter number {index}.")
    needle = selector.lower()
    exact = [
        adapter
        for adapter in adapters
        if needle
        in (
            adapter.friendly.lower(),
            adapter.description.lower(),
            adapter.name.lower(),
        )
    ]
    if len(exact) == 1:
        return exact[0]
    partial = [
        adapter
        for adapter in adapters
        if needle in adapter.friendly.lower()
        or needle in adapter.description.lower()
        or needle in adapter.name.lower()
    ]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise LookupError(f"No adapter matches {selector!r}.")
    choices = ", ".join(
        f"{index + 1}={adapter.friendly}"
        for index, adapter in enumerate(adapters)
        if adapter in partial
    )
    raise LookupError(f"Ambiguous adapter name; use a number: {choices}")


def pick_adapter(adapters: List[Adapter], selector: Optional[str]) -> Adapter:
    if selector:
        return match_adapter(adapters, selector)
    if not sys.stdin.isatty():
        raise LookupError(
            "No adapter selected. Use --iface NAME (or --list to see them)."
        )
    print_adapters(adapters)
    while True:
        try:
            answer = input("Select adapter number (or part of its name) [1]: ")
        except EOFError:
            raise LookupError("No adapter selected.")
        answer = answer.strip() or "1"
        try:
            return match_adapter(adapters, answer)
        except LookupError as exc:
            print(f"  {exc}")


def open_adapter(lib, adapter: Adapter, promiscuous: bool = False):
    error_buffer = ctypes.create_string_buffer(256)
    handle = lib.pcap_open_live(
        adapter.name.encode("utf-8", "surrogateescape"),
        65535,
        1 if promiscuous else 0,
        100,    # read timeout (ms)
        error_buffer,
    )
    if not handle:
        message = _decode(error_buffer.value) or "unknown error"
        raise RuntimeError(
            f"Cannot open adapter {adapter.friendly!r}: {message}\n"
            "Run as Administrator (run.bat does this automatically)."
        )
    return handle


def send_frame(lib, handle, frame: bytes) -> None:
    rc = lib.pcap_sendpacket(handle, frame, len(frame))
    if rc != 0:
        message = _decode(lib.pcap_geterr(handle)) or f"pcap error {rc}"
        raise RuntimeError(f"Sending failed: {message}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cdp_advertiser.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Send CDP frames from this Windows PC so a Cisco switch shows it "
            "in 'show cdp neighbors'."
        ),
        epilog=(
            "examples:\n"
            "  python cdp_advertiser.py --list\n"
            "  python cdp_advertiser.py --iface Ethernet\n"
            "  python cdp_advertiser.py --iface Ethernet --hostname LAB-SW2 "
            "--capabilities switch,igmp\n"
            "  python cdp_advertiser.py --iface 1 --interval 30 --vlan 10\n"
        ),
    )
    parser.add_argument("--list", action="store_true", help="list adapters and exit")
    parser.add_argument(
        "-i", "--iface", metavar="NAME",
        help="adapter name, description, or number from --list",
    )
    parser.add_argument(
        "--hostname", default=socket.gethostname(),
        help="CDP Device ID (default: this computer's name)",
    )
    parser.add_argument(
        "--platform", default="cisco WS-C2960-24TT-L",
        help="CDP Platform string (default: %(default)s)",
    )
    parser.add_argument(
        "--port", default="GigabitEthernet0/1", dest="port_id",
        help="CDP Port ID advertised to the switch (default: %(default)s)",
    )
    parser.add_argument(
        "--version-string", default=DEFAULT_VERSION, metavar="TEXT",
        help="CDP software version text",
    )
    parser.add_argument(
        "--capabilities", type=parse_capabilities,
        default=CAPABILITIES["switch"] | CAPABILITIES["igmp"],
        metavar="LIST",
        help="comma list: router, switch, host, igmp, repeater, "
             "transparent-bridge, source-route-bridge, or a number "
             "(default: switch,igmp)",
    )
    parser.add_argument(
        "--ip", metavar="ADDR",
        help="IPv4 address to advertise (default: auto-detect on the adapter)",
    )
    parser.add_argument(
        "--no-address", action="store_true",
        help="do not send the Address TLV at all",
    )
    parser.add_argument(
        "--mac", type=parse_mac, metavar="AA:BB:CC:DD:EE:FF",
        help="source MAC to put in the frames (default: adapter's real MAC)",
    )
    parser.add_argument(
        "--vlan", type=int, metavar="N",
        help="also advertise this native VLAN (omitted by default to avoid "
             "native-VLAN mismatch messages on the switch)",
    )
    parser.add_argument(
        "--vtp-domain", metavar="NAME",
        help="optional VTP management domain string",
    )
    parser.add_argument(
        "--ttl", type=int, default=180, metavar="SEC",
        help="CDP holdtime in seconds, 1-255 (default: %(default)s)",
    )
    parser.add_argument(
        "--interval", type=float, default=60.0, metavar="SEC",
        help="seconds between advertisements (default: %(default)s)",
    )
    parser.add_argument(
        "--count", type=int, default=0, metavar="N",
        help="stop after N frames (default: 0 = run until Ctrl+C)",
    )
    parser.add_argument(
        "--half-duplex", action="store_true",
        help="advertise half duplex (default: full)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="build and print the frame, do not send anything",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="print the hex dump of every frame",
    )
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
        text_part = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in chunk
        )
        print(f"  {offset:04x}  {hex_part:<47}  {text_part}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)

    try:
        lib = load_wpcap()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.list:
        try:
            print_adapters(discover_adapters(lib))
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        return 0

    try:
        adapters = discover_adapters(lib)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if not adapters:
        print(
            "ERROR: no capture adapters were found.\n"
            "Install Npcap from https://npcap.com/#download and retry.",
            file=sys.stderr,
        )
        return 2

    try:
        adapter = pick_adapter(adapters, args.iface)
    except LookupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    source_mac = args.mac or adapter.mac
    if not source_mac:
        print(
            "ERROR: could not read the MAC address of the selected adapter.\n"
            "Pass it explicitly, for example --mac A4:BB:6D:11:22:33",
            file=sys.stderr,
        )
        return 2

    advertised_ip = None if args.no_address else (args.ip or adapter.ipv4)

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
    print(f"  Adapter     : {adapter.friendly} ({adapter.description})")
    print(f"  Device      : {adapter.name}")
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

    if os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
        print(
            "WARNING: this console is not elevated.  Npcap usually refuses raw\n"
            "         access to non-administrators; use run.bat if opening the\n"
            "         adapter fails.\n"
        )

    handle = None
    sent = 0
    try:
        handle = open_adapter(lib, adapter)
        print(
            f"Sending to {format_mac(CDP_DST_MAC)} every {args.interval:g}s. "
            "Press Ctrl+C to stop."
        )
        while True:
            send_frame(lib, handle, frame)
            sent += 1
            stamp = time.strftime("%H:%M:%S")
            print(f"[{stamp}] sent #{sent} ({len(frame)} bytes)", flush=True)
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
        if handle:
            lib.pcap_close(handle)

    if sent:
        print(
            f"Sent {sent} advertisement(s). The switch drops the neighbor "
            f"about {args.ttl}s after the last one."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
