<p align="center">
  <img src="assets/logo-title.svg" width="420" alt="BandWick">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/status-early%20development-yellow.svg" alt="Status: early development">
</p>

BandWick is a self-hosted network monitor and bandwidth controller that runs from your own computer. There's no router firmware to flash and no extra hardware to buy. It watches what's happening on your network and lets you decide how much bandwidth each device gets.

The name comes from wick, the part of a candle that controls how much fuel a flame draws. BandWick does the same job for your connection: it controls how much of it each device gets to use.

## How it works

BandWick runs a small local backend with the same network privileges as a tool like Wireshark. That backend:

1. Discovers devices on your LAN through ARP scanning.
2. Routes each device's traffic through your machine using ARP spoofing, so it can be observed and, eventually, throttled.
3. Serves a local web dashboard with live usage graphs and per-device bandwidth controls.

**Only run this against a network you own or administer.** The technique used here is the same one real man-in-the-middle attacks rely on. Running it against a network you don't control, like a school, an office, or a coffee shop, counts as packet interception and is illegal in most places. The only thing that makes it legitimate here is that it's your own network.

## Status

- [x] Device discovery (`backend/discovery.py`)
- [x] ARP spoofing and traffic interception (`backend/spoof.py`)
- [ ] Bandwidth shaping (per OS)
- [ ] Web dashboard
- [ ] Native window wrapper (pywebview)

## Getting started

```bash
cd backend
pip install -r requirements.txt
```

### Device discovery

```bash
# Linux / macOS
sudo python3 discovery.py

# Windows (requires Npcap: https://npcap.com/#download)
# Run PowerShell or cmd as Administrator, then:
python discovery.py
```

This prints JSON, one entry per device found:

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

`vendor` and `hostname` can come back `null` if the lookup fails. This happens often with MAC randomization on modern phones or devices with no reverse DNS entry, and it isn't a bug.

### ARP spoofing and interception

Find your gateway IP first (`ip route` on Linux, `route -n get default` on macOS, `ipconfig` on Windows), then pick a target IP from the discovery output above.

```bash
# Linux / macOS
sudo python3 spoof.py <target_ip> <gateway_ip>

# Windows (requires Npcap, run as Administrator)
# Run this once first, as Administrator:
#   netsh interface ipv4 set global forwarding=enabled
python spoof.py <target_ip> <gateway_ip>
```

This routes the target device's traffic through your machine so it can be observed, and later throttled once shaping is in place. Press Ctrl+C to stop. Both devices' ARP tables are restored to their real mappings automatically, whether that happens through a clean stop, an error, or Ctrl+C.

The same warning from above applies here: only run this against a device on your own network.

## Roadmap

- Bandwidth shaping per operating system, starting with Linux via `tc`
- A local web dashboard for live monitoring and per-device limits
- A native window wrapper using pywebview, so the dashboard runs without a browser

## Contributing

This project is in early, active development. Issues and pull requests are welcome, but expect things to move and change quickly for now.

## License

BandWick is released under the MIT License. See [LICENSE](LICENSE) for details.
