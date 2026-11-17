"""Target validation: the first line of defence against misuse."""
import ipaddress

from config import Config


def validate_target(target: str) -> str:
    """Return a normalised target or raise ValueError.

    Accepted: a single IP, a CIDR range (e.g. 192.168.1.0/24) or a host listed
    in Config.ALLOWED_HOSTS. Public IPs are refused unless ALLOW_PUBLIC=1.
    The value is never passed through a shell, but we still reject anything odd.
    """
    target = (target or "").strip()
    if not target or len(target) > 64:
        raise ValueError("Enter a target (IP, CIDR range or scanme.nmap.org).")
    if target.lower() in Config.ALLOWED_HOSTS:
        return target.lower()
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise ValueError("Invalid target. Use an IP address or a CIDR range like 192.168.1.0/24.")
    if net.num_addresses > Config.MAX_HOSTS:
        raise ValueError(f"Range too large (max {Config.MAX_HOSTS} addresses).")
    if not Config.ALLOW_PUBLIC and not (net.is_private or net.is_loopback):
        raise ValueError("Public addresses are blocked. Scan your own lab network or scanme.nmap.org.")
    return str(net)
