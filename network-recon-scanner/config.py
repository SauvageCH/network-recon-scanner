"""Central configuration. Override with environment variables."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    DB_PATH = os.environ.get("SCANNER_DB", os.path.join(BASE_DIR, "data", "scans.db"))
    NMAP_BIN = os.environ.get("NMAP_BIN", "nmap")
    SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "600"))  # seconds
    MAX_HOSTS = int(os.environ.get("MAX_HOSTS", "256"))        # max addresses per scan
    # Safety: by default only private/loopback ranges + the official test host.
    ALLOW_PUBLIC = os.environ.get("ALLOW_PUBLIC", "0") == "1"
    ALLOWED_HOSTS = {"scanme.nmap.org"}
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = int(os.environ.get("PORT", "5000"))
