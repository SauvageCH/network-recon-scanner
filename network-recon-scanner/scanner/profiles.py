"""Scan profiles = named sets of Nmap arguments."""

PROFILES = {
    "discovery": {
        "label": "Host discovery",
        "description": "Ping sweep only: which hosts are alive (no port scan).",
        "args": ["-sn", "-T4"],
    },
    "quick": {
        "label": "Quick scan",
        "description": "The 100 most common ports. Fast.",
        "args": ["-F", "-T4"],
    },
    "service": {
        "label": "Service detection",
        "description": "Top 1000 ports plus service/version detection (-sV).",
        "args": ["-sV", "-T4"],
    },
    "vuln": {
        "label": "Vulnerability scan",
        "description": "Service detection plus Nmap 'vuln' scripts. Slow and intrusive: lab only.",
        "args": ["-sV", "-T4", "--script", "vuln"],
    },
}
