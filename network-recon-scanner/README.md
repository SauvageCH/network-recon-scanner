# Network Reconnaissance & Vulnerability Scanner

Automated network scanner built with **Python** and **Nmap**, with a web dashboard.
It discovers hosts, lists open ports and services, flags risky exposures and outdated software,
stores scan history and exports reports. **100% free**: Python, Flask, SQLite and Nmap are all open source, no cloud, no API keys.

> **Warning:** use only on networks you own or have written permission to test. See [docs/LEGAL.md](docs/LEGAL.md).

## Features

- Four scan profiles: host discovery, quick scan, service/version detection, Nmap `vuln` scripts
- Rule-based analysis with severity levels (high / medium / low) and fix recommendations
- Web UI: start a scan, live status, results table, history, delete
- Export to JSON, CSV and standalone HTML report
- CLI mode for terminal use
- Safety by design: target validation, public IP blocking, no shell injection, consent checkbox, XSS-safe rendering
- Unit tests (standard library only)

## Project structure

```
network-recon-scanner/
├── README.md
├── LICENSE
├── requirements.txt        # only Flask
├── config.py               # settings
├── run.py                  # starts the web app
├── cli.py                  # command-line mode
├── scanner/                # scanning engine
│   ├── validators.py       # target checks
│   ├── profiles.py         # Nmap profiles
│   ├── nmap_runner.py      # runs Nmap
│   ├── parser.py           # Nmap XML -> dict
│   ├── vuln_checks.py      # risk rules
│   └── reporter.py         # JSON / CSV / HTML export
├── app/                    # Flask web app
│   ├── __init__.py
│   ├── routes.py           # pages + REST API
│   ├── storage.py          # SQLite
│   ├── templates/          # base.html, index.html
│   └── static/             # css/style.css, js/app.js
├── docs/                   # ARCHITECTURE.md, USAGE.md, LEGAL.md
├── tests/                  # unit tests
└── data/                   # SQLite database (created at runtime)
```

## Installation

### 1. Install Nmap (free)

| OS | Command |
|----|---------|
| Windows | Download the installer from https://nmap.org/download (includes Npcap), then reopen your terminal |
| Ubuntu / Debian | `sudo apt install nmap` |
| macOS | `brew install nmap` |

Check: `nmap --version`

### 2. Install the project

```bash
git clone https://github.com/<your-username>/network-recon-scanner.git
cd network-recon-scanner
python -m venv .venv

# Windows:        .venv\Scripts\activate
# Linux / macOS:  source .venv/bin/activate

pip install -r requirements.txt
```

## Launch

```bash
python run.py
```

Open **http://127.0.0.1:5000**, enter a target (try `127.0.0.1` or `scanme.nmap.org`), tick the authorisation box and click **Start scan**.

CLI alternative:

```bash
python cli.py 127.0.0.1 --profile service --out result.json
```

Run the tests:

```bash
python -m unittest discover -s tests -t .
```

## How it works

1. The browser sends `{target, profile, authorized}` to `POST /api/scans`.
2. `validators.py` checks the target (IP or CIDR, private only, size limit).
3. A background thread runs `nmap <profile flags> -oX - <target>`.
4. `parser.py` converts the XML to Python data; `vuln_checks.py` produces findings.
5. The result is saved in SQLite; the page polls until the scan is `done`.
6. You can export the report as JSON, CSV or HTML.

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/USAGE.md](docs/USAGE.md).

## Free lab for the demo

Install VirtualBox (free) and import **Metasploitable 2** with a *host-only* network, then scan its IP (e.g. `192.168.56.101`) with the *Vulnerability scan* profile. You will see FTP, Telnet, SMB, vsftpd 2.3.4 and more flagged.

## Limits

- Detection relies on Nmap output and a small rule set; it does not exploit anything and is not a replacement for Nessus or OpenVAS.
- No authentication: keep the server on `127.0.0.1`.
- OS detection (`-O`) needs admin rights and is not enabled by default.

## Ideas to extend (good for a report)

- Integrate the Vulners NSE script or the NVD API for CVE lookup
- Scheduled scans and diff between two scans
- PDF reports, user login, Docker image

## Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit: network recon and vulnerability scanner"
git branch -M main
git remote add origin https://github.com/<your-username>/network-recon-scanner.git
git push -u origin main
```

## License

MIT, see [LICENSE](LICENSE). Replace `<your name>` in the file.
