# Architecture

```
Browser (HTML/CSS/JS)
      |  JSON over HTTP
Flask routes (app/routes.py)
      |  starts a background thread per scan
scanner/validators.py   -> checks the target is allowed
scanner/nmap_runner.py  -> runs `nmap ... -oX -` (subprocess, no shell)
scanner/parser.py       -> XML -> Python dict
scanner/vuln_checks.py  -> rules -> findings + summary
app/storage.py          -> SQLite (data/scans.db)
scanner/reporter.py     -> JSON / CSV / HTML export
```

## Modules

| File | Role |
|------|------|
| `config.py` | Settings (timeouts, limits, allowed targets), overridable via env vars |
| `scanner/profiles.py` | The Nmap argument sets: discovery, quick, service, vuln |
| `scanner/validators.py` | Accepts IPs/CIDR only; blocks public IPs, huge ranges and anything with shell characters |
| `scanner/nmap_runner.py` | Calls Nmap with an argument list and a timeout |
| `scanner/parser.py` | Reads Nmap XML into hosts, ports, services, scripts |
| `scanner/vuln_checks.py` | Three checks: risky ports, outdated versions, Nmap `vuln` script output |
| `scanner/reporter.py` | Builds export files |
| `app/storage.py` | CRUD on the `scans` table |
| `app/routes.py` | Web page + REST API |
| `app/static/js/app.js` | Form, polling, rendering (safe DOM, no `innerHTML`) |
| `cli.py` | Same engine from the terminal |

## Scan lifecycle

`queued` -> `running` -> `done` or `error`. The browser polls `GET /api/scans/<id>` every 2 s.

## API

| Method | URL | Purpose |
|--------|-----|---------|
| POST | `/api/scans` | Body `{target, profile, authorized}`; returns `{id}` |
| GET | `/api/scans` | Last 50 scans |
| GET | `/api/scans/<id>` | One scan with full result |
| DELETE | `/api/scans/<id>` | Remove a scan |
| GET | `/api/scans/<id>/export?fmt=json\|csv\|html` | Download a report |

## Security decisions

- No `shell=True`; target is validated before use.
- Server binds to `127.0.0.1`; there is no login, so never expose it publicly.
- Banners from scanned hosts are untrusted: the UI uses `textContent`, the HTML report uses `html.escape` (prevents XSS).
- Consent checkbox required for every scan.
