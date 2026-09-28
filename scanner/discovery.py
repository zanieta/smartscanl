"""Bounded, unprivileged discovery; no service or vulnerability scans."""
import ipaddress
import subprocess
import xml.etree.ElementTree as ET

PRIVATE = tuple(ipaddress.ip_network(cidr) for cidr in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


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
    root = ET.fromstring(result.stdout)
    hosts = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        for address in host.findall("address"):
            if address.get("addrtype") != "ipv4":
                continue
            ip = ipaddress.ip_address(address.get("addr", ""))
            if ip in network:
                hosts.add(str(ip))
    return [{"ip": ip, "network": str(network)} for ip in
            sorted(hosts, key=ipaddress.ip_address)]
