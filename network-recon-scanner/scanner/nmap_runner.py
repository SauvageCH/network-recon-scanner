"""Runs Nmap as a subprocess and returns its XML output."""
import shutil
import subprocess

from config import Config
from scanner.profiles import PROFILES


class NmapError(RuntimeError):
    pass


def nmap_available() -> bool:
    return shutil.which(Config.NMAP_BIN) is not None


def run_scan(target: str, profile: str) -> str:
    """Execute Nmap and return the XML report (stdout of `-oX -`)."""
    if profile not in PROFILES:
        raise NmapError(f"Unknown profile: {profile}")
    if not nmap_available():
        raise NmapError("Nmap is not installed or not in PATH. See README > Installation.")
    # List form + no shell=True => no command injection possible.
    cmd = [Config.NMAP_BIN, *PROFILES[profile]["args"], "-oX", "-", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=Config.SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise NmapError(f"Scan timed out after {Config.SCAN_TIMEOUT}s.")
    if proc.returncode != 0:
        raise NmapError(proc.stderr.strip() or "Nmap failed.")
    return proc.stdout
