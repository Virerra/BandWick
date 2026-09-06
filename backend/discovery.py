"""
bandwick.discovery

Discovers devices on the local subnet via ARP scanning, then enriches
each result with a best-guess vendor (from the MAC OUI) and hostname
(via reverse DNS).

Requires root/admin privileges to send raw ARP frames:
  - Linux/Mac:  sudo python3 discovery.py
  - Windows:    run as Administrator, with Npcap installed
                (https://npcap.com/#download)
"""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import List, Optional

from mac_vendor_lookup import MacLookup
from scapy.all import ARP, Ether, srp


@dataclass
class Device:
    ip: str
    mac: str
    vendor: Optional[str] = None
    hostname: Optional[str] = None


def get_local_subnet() -> str:
    """
    Best-effort detection of the local IPv4 subnet in CIDR form,
    e.g. '192.168.1.0/24'. Tries the OS routing table first, then
    falls back to guessing a /24 around the machine's own IP.
    """
    try:
        if sys.platform.startswith("linux"):
            out = subprocess.check_output(["ip", "-4", "route", "show"], text=True)
            for line in out.splitlines():
                if line.startswith("default"):
                    continue
                first_field = line.split()[0]
                if "/" in first_field:
                    return first_field
    except Exception:
        pass

    # Fallback for macOS/Windows, or if the above didn't find anything:
    # guess a /24 around this machine's own address.
    try:
        # Doesn't actually send packets (UDP/connect trick), just asks the
        # OS routing table which local interface would be used.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except Exception:
        local_ip = socket.gethostbyname(socket.gethostname())

    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def scan(subnet: Optional[str] = None, timeout: int = 3) -> List[Device]:
    """
    ARP-scans the given subnet (CIDR string, e.g. '192.168.1.0/24') and
    returns a list of Device objects for everything that answered.
    Auto-detects the subnet if none is given.
    """
    subnet = subnet or get_local_subnet()

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=timeout, verbose=False)

    devices = [Device(ip=received.psrc, mac=received.hwsrc) for _, received in answered]
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


def scan_to_json(subnet: Optional[str] = None) -> str:
    devices = scan(subnet)
    return json.dumps([asdict(d) for d in devices], indent=2)


if __name__ == "__main__":
    print("Scanning local subnet for devices (requires root/admin privileges)...", file=sys.stderr)
    print(scan_to_json())
