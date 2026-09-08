# ipspec

**IP and LAN information toolkit for Linux**

`ipspec` shows WAN/LAN details, scans local networks, measures bandwidth, monitors traffic, and can renew a FRITZ!Box WAN IP — all from one small Bash script.

**Version:** 4.0  
**Author:** Speefak (itoss@gmx.de)  
**License:** [CC BY-NC-SA](https://creativecommons.org/licenses/by-nc-sa/4.0/)

---

## Features

| Feature | Option | Description |
|--------|--------|-------------|
| Network overview | *(default)* | WAN IP, gateway, DNS, used interfaces (IPv4/IPv6, MAC) |
| All devices | `-v` | Same as default, including interfaces without an address |
| Device status (offline) | `-d` | List interfaces + MAC even without LAN/WAN |
| Simple LAN scan | `-sl` | Quick `nmap` of the local `/24` |
| Advanced netscan | `-ns` | Multi-network scan → CSV (`ip;mac;hostname;ports`) |
| Bandwidth test | `-bm` | Speedtest (download / upload / ping) |
| Live traffic | `-st` | `nload` (per interface) and/or `nethogs` (per process) |
| WAN IP log | `-lw` | Continuously log WAN IP changes |
| FRITZ!Box reconnect | `-fbr` | Force new WAN IP via UPnP |
| Dependency check | `-cfrp` | Detect and optionally install required packages |
| Monochrome | `-m` | Disable colors (can be combined with any option) |

---

## Requirements

- Linux (uses `ip`, `iproute2`, `dpkg`/`apt`)
- Bash

**Packages** (install via `./ipspec.sh -cfrp` or manually):

```text
lynx curl geoip-bin netcat nmap speedtest-cli nload nethogs
```

Optional but recommended:

- `python3` — required for `-ns` (XML → CSV)
- `column` — nicer CSV table output for `-ns`
- `nmcli` — richer DNS/connection labels (NetworkManager)
- root/sudo — for SYN scan (`-ns`), OS detection, and `nethogs`

---

## Installation

```bash
# clone
git clone https://github.com/<USER>/ipspec.git
cd ipspec

# make executable
chmod +x ipspec.sh

# optional: install system-wide
sudo cp ipspec.sh /usr/local/bin/ipspec
```

Or download a single release file and run it directly.

---

## Usage

```text
ipspec [option]

 -h          help
 -i          script information (name, version, path, size)
 -m          monochrome output (combine with other options)

 default     IP / LAN information (used devices only)
 -v          IP / LAN information (all devices)
 -d          device status + MAC (works offline)
 -sl         scan LAN (simple nmap of local /24)
 -ns         netscan (advanced multi-network scan → CSV)
               options after -ns:
                 -n "net1 net2"   network ranges
                 -p 1-1000        port range (default: 1-10000)
                 -o /path/file.csv
                 -f               fast mode (top 100 ports, no version detect)
 -bm         bandwidth measurement
 -st         show traffic (nload / nethogs)
 -lw         log WAN IP changes
 -fbr        renew FRITZ!Box WAN IP
 -cfrp       check / install required packages
```

Option order does not matter for modifiers (e.g. `-m -v` and `-v -m` both work).

---

## Examples

```bash
# standard overview (only interfaces that have an address)
ipspec

# all interfaces, monochrome
ipspec -v -m

# devices + MAC without network connectivity
ipspec -d

# quick local /24 scan
ipspec -sl

# advanced scan of several private nets (needs root for -sS)
sudo ipspec -ns

# scan one net, fast mode, custom output file
sudo ipspec -ns -n 192.168.1.0/24 -f -o /tmp/hosts.csv

# bandwidth test
ipspec -bm

# live traffic monitor
ipspec -st

# log WAN IP changes (Ctrl+C or any key to stop after countdown)
ipspec -lw

# force new FRITZ!Box WAN IP
ipspec -fbr

# install missing dependencies
ipspec -cfrp
```

---

## Netscan (`-ns`) details

- Scans each network **sequentially** with live status (phase / stats / timing).
- Default networks:  
  `192.168.1.0/24 192.168.2.0/24 192.168.5.0/24 192.168.10.0/24 192.168.20.0/24`
- Default ports: `1-10000` (or top 100 with `-f`).
- Output CSV: `/tmp/netscan_YYYYMMDD_HHMMSS.csv`  
  Format: `ip;mac;hostname;ports`
- MAC fallback via `ip neigh` when nmap cannot resolve MAC (e.g. routed hosts).
- As root: SYN scan (`-sS`) + OS detection; as user: TCP connect scan (`-sT`).

---

## Offline behaviour

- If there is **no LAN/WLAN address**, the script no longer aborts with an error.
- It runs the device list (`-d`) instead: interfaces, MAC addresses, and `not connected` where no IP is present.

---

## FRITZ!Box (`-fbr`)

Uses UPnP on the gateway (`ForceTermination`) to request a new WAN IP, then prints the old and new address. Works with typical FRITZ!Box models that expose WANIPConnection on port 49000.

---

## License

Creative Commons **Attribution–NonCommercial–ShareAlike** (CC BY-NC-SA).  
See the script header and [creativecommons.org](https://creativecommons.org/licenses/by-nc-sa/4.0/) for details.

---

## Changelog (summary)

| Version | Highlights |
|--------|------------|
| **4.0** | Stable release with integrated netscan, traffic tools, offline device list |
| 3.9 | Netscan as function (`-ns`), `-st` (nload/nethogs), `-d` offline devices, option order independence |
| 3.8 | Traffic monitoring planned (nload/nethogs) |
| 3.x | WAN IP log, DNS via nmcli, IPv6, monochrome, input option checks, LAN/WAN checks |
| 2.x | Core IP/LAN overview, formatting, device listing |

---

## Notes

- Geolocation uses `geoiplookup` (package `geoip-bin`).
- TOR status is checked via [check.torproject.org](https://check.torproject.org).
- Speedtest uses `speedtest-cli` (`--secure`); a short cooldown avoids overlapping runs.
- Colors can be disabled with `-m` for logs or limited terminals.

--------------------------------------------------------------------------------------------------------------

This script was created and published free of charge for the open source community.
If you find it useful and would like to support future development, consider making a small donation:

    Bitcoin (BTC): 33AXe8Z8XBuGKx9eHHmGnvbawrNYjSgDcM

    Ethereum (ETH): 0xa61d178EA84C2200A8617b51B4bCf98F87ff59Ff

    Solana (SOL): BDf5EgsN8fRUicYzeM8cuaNhL7zdty2qsEj2mC2jA4Fm

    Ripple (XRP): rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh

    Cardano (ADA): addr1q8anur2wvvc6pv3cpp30vv05makyra8huh0lk0yhdk6hcnlrzr27g03klu862usxqsru794d03gzkk8n86ta34n85z0svn5ams   

    USTether (USDT): 0xa61d178EA84C2200A8617b51B4bCf98F87ff59Ff


Thank you for your support! 🙏

