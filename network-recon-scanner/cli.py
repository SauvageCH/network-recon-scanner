"""Command-line mode:  python cli.py 192.168.1.0/24 --profile service --out report.json"""
import argparse
import json
import sys

from scanner import nmap_runner, parser, validators, vuln_checks
from scanner.profiles import PROFILES


def main():
    ap = argparse.ArgumentParser(description="Network recon & vulnerability scanner (Nmap)")
    ap.add_argument("target")
    ap.add_argument("--profile", choices=PROFILES, default="quick")
    ap.add_argument("--out", help="write JSON result to this file")
    args = ap.parse_args()
    try:
        target = validators.validate_target(args.target)
        result = parser.parse_xml(nmap_runner.run_scan(target, args.profile))
    except (ValueError, nmap_runner.NmapError) as exc:
        sys.exit(f"Error: {exc}")
    result["findings"] = vuln_checks.analyze(result)
    result["summary"] = vuln_checks.summarize(result, result["findings"])
    for f in result["findings"]:
        print(f"[{f['severity'].upper():6}] {f['host']}:{f['port']} {f['title']}")
    print(result["summary"])
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(result, fh, indent=2)


if __name__ == "__main__":
    main()
