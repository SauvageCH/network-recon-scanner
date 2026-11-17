"""Export a finished scan as JSON, CSV or a standalone HTML report."""
import csv
import html
import io
import json


def to_json(scan: dict) -> str:
    return json.dumps(scan, indent=2)


def to_csv(scan: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "port", "protocol", "state", "service", "product", "version"])
    for h in scan["result"]["hosts"]:
        for p in h["ports"]:
            w.writerow([h["ip"], p["port"], p["protocol"], p["state"], p["service"], p["product"], p["version"]])
    return buf.getvalue()


def to_html(scan: dict) -> str:
    e = html.escape
    r = scan["result"]
    rows = "".join(
        f"<tr><td>{e(h['ip'])}</td><td>{p['port']}/{e(p['protocol'])}</td><td>{e(p['state'])}</td>"
        f"<td>{e(p['service'])}</td><td>{e((p['product'] + ' ' + p['version']).strip())}</td></tr>"
        for h in r["hosts"] for p in h["ports"])
    finds = "".join(
        f"<li><b>[{e(f['severity'])}]</b> {e(f['host'])}:{f['port']} - {e(f['title'])}<br>"
        f"<small>{e(f['detail'])} Fix: {e(f['recommendation'])}</small></li>" for f in r["findings"])
    return f"""<!doctype html><meta charset="utf-8"><title>Scan #{scan['id']}</title>
<style>body{{font:15px system-ui;max-width:900px;margin:2rem auto}}td,th{{border:1px solid #ccc;padding:4px 8px}}table{{border-collapse:collapse}}</style>
<h1>Scan report #{scan['id']}</h1><p>Target: {e(scan['target'])} | Profile: {e(scan['profile'])} | Date: {e(scan['created_at'])}</p>
<h2>Findings</h2><ul>{finds or '<li>No findings.</li>'}</ul>
<h2>Ports</h2><table><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>{rows}</table>"""
