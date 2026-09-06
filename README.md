<p align="center">
  <img src="assets/logo.svg" width="120" alt="Bandwick logo — hand-drawn figure mark">
</p>

# Bandwick

Self-hosted network monitor + per-device bandwidth control, run from your
own machine — no router firmware or dedicated hardware required.

The name plays on "wick" — the thing that controls how a flame draws
fuel — for a tool that controls how much of the connection each device
draws.

## How it works

Runs a small local backend with elevated network privileges (same
privilege level as Wireshark) that:

1. Discovers devices on your LAN via ARP scanning
2. Routes their traffic through your machine (ARP spoofing) to observe
   and, next, throttle it
3. Serves a local HTML dashboard for live usage graphs and per-device
   bandwidth caps

**Only ever point this at a network you own or administer.** Doing the
same thing on a network you don't control (school, office, café Wi-Fi)
is packet interception and is illegal in most places.

## Status

- [x] Device discovery (`backend/discovery.py`)
- [x] ARP spoofing / traffic interception (`backend/spoof.py`)
- [ ] Bandwidth shaping (per-OS)
- [ ] Web dashboard
- [ ] Native window wrapper (pywebview)

## Setup

```bash
cd backend
pip install -r requirements.txt
```

### Run device discovery

```bash
# Linux / macOS
sudo python3 discovery.py

# Windows (requires Npcap: https://npcap.com/#download)
# Run PowerShell/cmd as Administrator, then:
python discovery.py
```

Outputs JSON, one entry per device found:

```json
[
  {
    "ip": "192.168.1.42",
    "mac": "aa:bb:cc:dd:ee:ff",
    "vendor": "Apple, Inc.",
    "hostname": "johns-iphone.lan"
  }
]
```

`vendor` and `hostname` may be `null` if the lookup fails (private MAC
randomization on modern phones, no reverse DNS entry, etc.) — this is
expected and not a bug.

### Run ARP spoofing / interception

Find your gateway IP first (`ip route` on Linux, `route -n get default`
on macOS, `ipconfig` on Windows) and a target device's IP from the
discovery output above, then:

```bash
# Linux / macOS
sudo python3 spoof.py <target_ip> <gateway_ip>

# Windows (requires Npcap, and run as Administrator)
# Also run this first, once, as Administrator:
#   netsh interface ipv4 set global forwarding=enabled
python spoof.py <target_ip> <gateway_ip>
```

This routes the target device's traffic through your machine so it can
be observed (and, once shaping lands, throttled). Press `Ctrl+C` to stop
— both devices' ARP tables are automatically restored to their real
mappings on exit, whether that's a clean stop, an error, or Ctrl+C.

**Only run this against a device on your own network.** See the warning
above — this is the same technique real MITM attacks use; the only
thing that makes it legitimate here is that it's your network.

