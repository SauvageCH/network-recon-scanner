# Usage guide

## Scan profiles

| Profile | Nmap flags | Use it for |
|---------|-----------|------------|
| Host discovery | `-sn -T4` | Listing live hosts |
| Quick scan | `-F -T4` | Fast look at 100 common ports |
| Service detection | `-sV -T4` | Software names and versions |
| Vulnerability scan | `-sV -T4 --script vuln` | Known-flaw checks (slow, noisy, lab only) |

## Safe practice targets (free)

- `scanme.nmap.org`: provided by the Nmap project for testing (be polite, no heavy scans).
- Your own machine: `127.0.0.1`.
- A lab VM: Metasploitable 2 or DVWA in VirtualBox (host-only network). It has many deliberate flaws, ideal for the demo.

## CLI

```bash
python cli.py 127.0.0.1 --profile service --out result.json
```

## Reading the results

- **High**: likely exploitable or dangerous exposure (Telnet, SMB, backdoored versions, `vuln` script hits).
- **Medium**: risky exposure or outdated software.
- **Low**: worth reviewing.
- "No findings" never proves a host is safe; the rule set is small.

## Configuration (environment variables)

`PORT`, `HOST`, `SCAN_TIMEOUT`, `MAX_HOSTS`, `NMAP_BIN`, `SCANNER_DB`, `ALLOW_PUBLIC=1` (only if you have authorisation).
