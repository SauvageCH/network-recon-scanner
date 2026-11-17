"""Rule-based risk analysis on top of the parsed Nmap data.

This is NOT an exploit engine. It flags: risky exposed services, known-bad
software versions, and findings reported by Nmap's own `vuln` scripts.
"""
import re

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# port -> (severity, title, detail, recommendation)
RISKY_PORTS = {
    21: ("medium", "FTP exposed", "FTP sends credentials in clear text.", "Use SFTP/FTPS or restrict access."),
    23: ("high", "Telnet exposed", "Telnet is unencrypted and often has weak credentials.", "Disable Telnet, use SSH."),
    25: ("low", "SMTP exposed", "Open mail relay and user enumeration are possible.", "Restrict relay, require auth."),
    69: ("medium", "TFTP exposed", "TFTP has no authentication.", "Disable or firewall TFTP."),
    110: ("low", "POP3 exposed", "POP3 is unencrypted by default.", "Use POP3S."),
    135: ("medium", "MS-RPC exposed", "Common target for Windows attacks.", "Block at the firewall."),
    139: ("medium", "NetBIOS exposed", "Leaks host information.", "Disable NetBIOS over TCP/IP."),
    445: ("high", "SMB exposed", "SMB has a long history of critical flaws (e.g. EternalBlue).", "Patch and block from untrusted networks."),
    512: ("high", "rexec exposed", "Legacy remote execution, no encryption.", "Disable r-services."),
    513: ("high", "rlogin exposed", "Legacy remote login, no encryption.", "Disable r-services."),
    514: ("high", "rsh exposed", "Legacy remote shell, no encryption.", "Disable r-services."),
    1433: ("medium", "MS SQL exposed", "Database reachable over the network.", "Restrict to application hosts."),
    3306: ("medium", "MySQL exposed", "Database reachable over the network.", "Bind to localhost / firewall it."),
    3389: ("medium", "RDP exposed", "RDP is a prime brute-force and ransomware entry point.", "Use VPN + MFA."),
    5432: ("medium", "PostgreSQL exposed", "Database reachable over the network.", "Restrict to application hosts."),
    5900: ("medium", "VNC exposed", "VNC is often weakly protected.", "Tunnel through SSH/VPN."),
    6379: ("high", "Redis exposed", "Redis often runs without authentication.", "Bind to localhost, enable auth."),
    27017: ("high", "MongoDB exposed", "MongoDB is frequently exposed without auth.", "Enable auth, firewall the port."),
}

# (product regex, version regex, severity, message)
BAD_VERSIONS = [
    (r"vsftpd", r"^2\.3\.4$", "high", "vsftpd 2.3.4 contains a known backdoor (CVE-2011-2523)."),
    (r"OpenSSH", r"^[1-6]\.", "medium", "Outdated OpenSSH (< 7.0) with known vulnerabilities."),
    (r"Apache httpd", r"^2\.[0-3]\.", "medium", "Outdated Apache httpd (< 2.4)."),
    (r"ProFTPD", r"^1\.3\.[0-4]", "medium", "Outdated ProFTPD with known vulnerabilities."),
    (r"Microsoft IIS", r"^[1-6]\.", "medium", "Outdated Microsoft IIS."),
    (r"Samba", r"^[1-3]\.", "medium", "Outdated Samba."),
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _finding(host, port, sev, title, detail, reco):
    return {"host": host, "port": port, "severity": sev, "title": title,
            "detail": detail, "recommendation": reco}


def analyze(result: dict) -> list:
    findings = []
    for host in result["hosts"]:
        ip = host["ip"]
        for p in host["ports"]:
            if p["state"] != "open":
                continue
            num = p["port"]
            if num in RISKY_PORTS:
                sev, title, detail, reco = RISKY_PORTS[num]
                findings.append(_finding(ip, num, sev, title, detail, reco))
            product = p["product"]
            for prod_re, ver_re, sev, msg in BAD_VERSIONS:
                if re.search(prod_re, product, re.I) and re.search(ver_re, p["version"] or ""):
                    findings.append(_finding(ip, num, sev, f"Outdated software: {product} {p['version']}", msg,
                                             "Upgrade to a supported, patched version."))
            for s in p["scripts"]:
                out = s["output"]
                if "VULNERABLE" in out.upper() and "NOT VULNERABLE" not in out.upper():
                    cves = sorted(set(CVE_RE.findall(out)))
                    findings.append(_finding(ip, num, "high", f"Nmap script {s['id']} reports a vulnerability",
                                             ", ".join(cves) or out.strip()[:200],
                                             "Apply vendor patches; verify manually."))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["host"], f["port"] or 0))
    return findings


def summarize(result: dict, findings: list) -> dict:
    up = [h for h in result["hosts"] if h["status"] == "up"]
    open_ports = sum(1 for h in up for p in h["ports"] if p["state"] == "open")
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    return {"hosts_up": len(up), "open_ports": open_ports, "severity": counts}
