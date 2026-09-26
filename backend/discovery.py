"""
bandwick.discovery

Discovers devices on the local subnet via ARP scanning, then enriches
each result with a best-guess vendor (from the MAC OUI) and hostname
(via reverse DNS).

Requires root/admin privileges to send raw ARP frames:
  - Linux/Mac:  sudo python3 discovery.py
  - Windows:    run as Administrator, with Npcap installed
                (https://npcap.com/#download)

On machines with more than one network adapter (VPN clients, Hyper-V
switches, virtual bridges, and similar), scapy's default interface
guess isn't always the one actually connected to your LAN. This module
resolves the interface the same way the OS would for a normal internet
connection, and sends the ARP broadcast explicitly on that interface,
rather than leaving it to scapy's default.

It also runs a quick ICMP ping sweep before the ARP sweep. Some
devices in WiFi power-saving mode don't bother answering a broadcast
"who has" ARP request, since the access point only delivers broadcast
frames to sleeping clients at fixed beacon intervals, but they do wake
up for a ping addressed directly to them. Anything that answers a ping
but got missed by the ARP broadcast gets one more direct, targeted ARP
request before being given up on.

By default this probes all 254 possible addresses in the /24, since
there's no general way to know a router's DHCP pool ahead of time. If
you already know your router only ever hands out addresses in a
narrower range, --host-range trims the sweep to just that range, which
noticeably speeds things up.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import socket
import sys
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

from mac_vendor_lookup import MacLookup
from scapy.all import ARP, ICMP, IP, Ether, conf, get_working_ifaces, sr, srp, srp1

# The sweep below can hit every address in the subnet, most of which have no
# device behind them. For each of those, scapy logs a "MAC address to reach
# destination not found, using broadcast" warning -- harmless, since it still
# delivers the packet, but noisy across a couple hundred addresses. Quieting
# it down to errors only.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


@dataclass
class Device:
    ip: str
    mac: str
    vendor: Optional[str] = None
    hostname: Optional[str] = None


def get_default_iface_and_subnet() -> Tuple[str, str]:
    """
    Returns (iface, subnet_cidr) for whichever interface the OS would
    use to reach the internet. This is also the interface the ARP
    broadcast needs to go out on -- if it doesn't match your real LAN
    adapter, the scan will only ever find your own machine.
    """
    iface, my_ip, _gateway_ip = conf.route.route("0.0.0.0")
    network = ipaddress.ip_network(f"{my_ip}/24", strict=False)
    return iface, str(network)


def list_interfaces() -> None:
    """Prints every interface scapy can see, to help pick one manually
    if auto-detection picks the wrong adapter."""
    for iface in get_working_ifaces():
        print(f"  {iface.name!r:35} ip={iface.ip}")


def build_host_list(subnet: str, host_range: Optional[Tuple[int, int]] = None) -> List[str]:
    """
    Builds the list of host IPs to probe within `subnet`. If `host_range`
    is given as (start, end), only addresses whose last octet falls in
    that inclusive range are included. Devices outside a narrowed range
    (including the gateway itself, if it's outside the range you give)
    won't show up -- this is a speed/coverage tradeoff you're opting into,
    not the safe default.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = network.hosts()
    if host_range is not None:
        start, end = host_range
        hosts = (ip for ip in hosts if start <= int(str(ip).split(".")[-1]) <= end)
    return [str(ip) for ip in hosts]


def ping_sweep(hosts: List[str], timeout: float = 3) -> List[str]:
    """
    Sends an ICMP echo request to every address in `hosts` at once and
    returns the ones that answered. Catches devices that ignore a
    broadcast ARP request but still respond to a request addressed
    directly to them, and tends to wake a device up enough that a
    follow-up direct ARP request succeeds too.
    """
    try:
        answered, _ = sr(IP(dst=hosts) / ICMP(), timeout=timeout, verbose=False)
    except Exception:
        # ICMP can be filtered on some networks -- the ARP sweep in scan()
        # still runs regardless, this is purely a supplementary catch-all.
        return []
    return [received.src for _, received in answered]


def get_mac(ip: str, timeout: float = 2) -> Optional[str]:
    """Resolves a single IP's MAC via one direct, targeted ARP request."""
    answer = srp1(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, verbose=False
    )
    return answer.hwsrc if answer else None


def scan(
    subnet: Optional[str] = None,
    iface: Optional[str] = None,
    timeout: int = 3,
    host_range: Optional[Tuple[int, int]] = None,
) -> List[Device]:
    """
    ARP-scans the given subnet (CIDR string, e.g. '192.168.1.0/24') on
    the given interface, and returns a list of Device objects for
    everything that answered. Auto-detects subnet and interface if not
    given, and backstops the broadcast ARP sweep with a ping sweep for
    devices that only respond to traffic addressed directly to them.
    """
    if subnet is None or iface is None:
        detected_iface, detected_subnet = get_default_iface_and_subnet()
        subnet = subnet or detected_subnet
        iface = iface or detected_iface

    hosts = build_host_list(subnet, host_range)

    responsive_ips = set(ping_sweep(hosts, timeout=timeout))

    arp_request = ARP(pdst=hosts)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_request, timeout=timeout, iface=iface, verbose=False)
    found = {received.psrc: received.hwsrc for _, received in answered}

    # Anything that answered a ping but was missed by the broadcast ARP
    # sweep gets one more shot, addressed only to it.
    for ip in responsive_ips - found.keys():
        mac = get_mac(ip, timeout=timeout)
        if mac:
            found[ip] = mac

    devices = [Device(ip=ip, mac=mac) for ip, mac in found.items()]
    _enrich(devices)
    return devices


def _enrich(devices: List[Device]) -> None:
    """Fills in vendor (via MAC OUI lookup) and hostname (via reverse DNS)."""
    try:
        mac_lookup = MacLookup()
    except Exception:
        mac_lookup = None

    for device in devices:
        if mac_lookup is not None:
            try:
                device.vendor = mac_lookup.lookup(device.mac)
            except Exception:
                device.vendor = None
        try:
            device.hostname = socket.gethostbyaddr(device.ip)[0]
        except Exception:
            device.hostname = None


def scan_to_json(subnet: Optional[str] = None, iface: Optional[str] = None) -> str:
    devices = scan(subnet, iface)
    return json.dumps([asdict(d) for d in devices], indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan the local network for connected devices.")
    parser.add_argument("--subnet", help="CIDR subnet to scan, e.g. 192.168.1.0/24 (auto-detected if omitted)")
    parser.add_argument("--iface", help="Network interface to scan on (auto-detected if omitted)")
    parser.add_argument(
        "--list-ifaces", action="store_true",
        help="List available network interfaces and exit (use this if the scan only finds your own machine)",
    )
    parser.add_argument(
        "--timeout", type=int, default=3,
        help="Seconds to wait for replies, applies to both the ping and ARP sweeps (default: 3, try higher if a known device is missing)",
    )
    parser.add_argument(
        "--host-range", nargs=2, type=int, metavar=("START", "END"),
        help="Only scan addresses whose last number falls in this range, e.g. --host-range 100 150. "
             "Speeds up the scan a lot if you know your router's DHCP pool, but anything outside "
             "the range (including the gateway, if it's outside it) won't show up.",
    )
    args = parser.parse_args()

    if args.list_ifaces:
        list_interfaces()
        sys.exit(0)

    host_range = tuple(args.host_range) if args.host_range else None

    print("Scanning local subnet for devices (requires root/admin privileges)...", file=sys.stderr)
    devices = scan(subnet=args.subnet, iface=args.iface, timeout=args.timeout, host_range=host_range)
    print(json.dumps([asdict(d) for d in devices], indent=2))
