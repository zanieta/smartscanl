"""Bounded, unprivileged discovery; no service or vulnerability scans."""
import ipaddress
import json
import re
import subprocess
import xml.etree.ElementTree as ET

PRIVATE = tuple(ipaddress.ip_network(cidr) for cidr in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def neighbor_addresses() -> dict:
    """Read the local neighbor cache only; do not send extra probes."""
    try:
        result = subprocess.run(["ip", "-j", "neigh", "show"], capture_output=True,
                                check=True, timeout=5)
        if len(result.stdout) > 1_000_000:
            return {}
        rows = json.loads(result.stdout)
        return {r['dst']: r['lladdr'].lower() for r in rows if isinstance(r, dict)
                and isinstance(r.get('dst'), str)
                and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", r.get('lladdr', ''))}
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return {}


def approved_networks(value: str) -> list:
    networks = []
    for item in value.split(","):
        if not item.strip():
            continue
        network = ipaddress.ip_network(item.strip(), strict=True)
        if network.version != 4 or not any(network.subnet_of(p) for p in PRIVATE):
            raise ValueError("Only explicit RFC1918 IPv4 networks are allowed.")
        if network.num_addresses > 256:
            raise ValueError("Each network must contain at most 256 addresses (/24 or smaller).")
        if any(network.overlaps(other) for other in networks):
            raise ValueError("Discovery networks must not overlap.")
        networks.append(network)
    if not networks or len(networks) > 4 or sum(n.num_addresses for n in networks) > 1024:
        raise ValueError("Configure 1 to 4 networks, with at most 1024 total addresses.")
    return networks


def discover(network) -> list[dict]:
    result = subprocess.run(
        ["nmap", "--unprivileged", "-sn", "-n", "-PS80,443", "--max-retries", "1",
         "--host-timeout", "5s", "-oX", "-", str(network)],
        capture_output=True, timeout=90, check=True,
    )
    if len(result.stdout) > 4_000_000:
        raise ValueError("Discovery response exceeds the allowed size.")
    root = ET.fromstring(result.stdout)
    hosts = {}
    neighbors = neighbor_addresses()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        for address in host.findall("address"):
            if address.get("addrtype") != "ipv4":
                continue
            ip = ipaddress.ip_address(address.get("addr", ""))
            if ip in network:
                mac = host.find("address[@addrtype='mac']")
                hostname = host.find("hostnames/hostname")
                hosts[str(ip)] = {
                    "ip": str(ip), "network": str(network), "status": "Responded",
                    "hostname": hostname.get("name", "")[:253] if hostname is not None else "",
                    "mac": mac.get("addr", "")[:32] if mac is not None else neighbors.get(str(ip), ""),
                    "vendor": mac.get("vendor", "")[:160] if mac is not None else "",
                }
    return [hosts[ip] for ip in sorted(hosts, key=ipaddress.ip_address)]
