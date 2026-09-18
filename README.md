# Bloodline OSINT

A desktop OSINT (Open-Source Intelligence) toolkit built with Python and Tkinter, designed for **lawful** research and investigation purposes.

## Features

- **Web / IP Analyze** — GeoIP, ISP, ASN, map
- **UserFind** — 55+ platform parallel username search
- **Mail Analyze** — MX / TXT / NS / A records + SMTP verification
- **Phone Analyze** — country / operator / validity (global MCC/MNC operator database)
- **WHOIS** — raw two-step IANA query
- **DNS Lookup** — A / MX / NS / TXT / CNAME / AAAA, Zone Transfer & DNSSEC check
- **Subdomain Scanner** — crt.sh + brute-force (120+ wordlist)
- **Port Scanner** — open port detection with 25+ service signatures
- **SSL / TLS Analysis** — certificate info + HSTS check
- **Breach Check** — HaveIBeenPwned (full API mode or keyless k-Anonymity)
- **Shodan** — API mode or keyless InternetDB mode
- **Batch Scanning** — scan targets from a file
- **History, Favorites & HTML Report**
- **Proxy Support** — off / manual / random proxy rotation

## Requirements

- Python 3.10+
- Windows (a `.bat` installer is included)

## Installation

```bash
pip install -r requ/requirements.txt
```

Or on Windows, double-click `requ/requ-installer.bat`.

## Usage

```bash
python app/bloodlineosintnew.py
```

`app/bloodlineosintold.py` is the legacy v2.0 edition.

## Legal Notice

This tool is intended for **lawful OSINT research only**. Collecting personal data or any illegal use is strictly prohibited. The authors accept no liability for misuse.

## Contributors

- **Acsida** ([@acsida](https://github.com/acsida)) — creator & developer
