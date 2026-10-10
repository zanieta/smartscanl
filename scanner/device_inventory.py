"""Conservative inventory hints; no login, cloud lookup or service probes."""
import ipaddress
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
OUI_FILES = (Path('/usr/share/nmap/nmap-mac-prefixes'), Path('/usr/local/share/nmap/nmap-mac-prefixes'))
TYPE_HINTS = {
    'Phone': ('iphone', 'android', 'phone'),
    'Tablet': ('ipad', 'tablet'),
    'Computer': ('desktop', 'laptop', 'macbook', 'workstation'),
    'Printer': ('printer', 'laserjet', 'officejet'),
    'Camera': ('camera', 'ipcam'),
    'Router / gateway': ('router', 'gateway'),
    'Switch': ('switch',),
    'TV / media device': ('smarttv', 'chromecast', 'roku'),
}


def gateways() -> set[str]:
    try:
        result = subprocess.run(['ip', '-j', '-4', 'route', 'show', 'default'],
                                capture_output=True, check=True, timeout=2)
        if len(result.stdout) > 100_000:
            return set()
        return {str(ipaddress.IPv4Address(row['gateway'])) for row in json.loads(result.stdout)
                if isinstance(row, dict) and row.get('gateway')}
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return set()


def oui_vendors() -> dict[str, str]:
    for path in OUI_FILES:
        try:
            if path.stat().st_size > 8_000_000:
                continue
            rows = {}
            for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2 and re.fullmatch('[0-9A-Fa-f]{6}', parts[0]):
                    rows[parts[0].upper()] = parts[1][:160]
            return rows
        except OSError:
            continue
    return {}


def hostname_for(ip: str) -> str:
    """Use the host's configured name service, with a hard process timeout."""
    try:
        ipaddress.IPv4Address(ip)
        result = subprocess.run(['getent', 'hosts', ip], capture_output=True,
                                timeout=1, check=True)
        if len(result.stdout) > 16_384:
            return ''
        parts = result.stdout.decode('utf-8', errors='replace').split()
        if len(parts) >= 2 and parts[0] == ip and re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', parts[1]):
            return parts[1].rstrip('.')
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return ''


def classify(host: dict, gateway_ips: set[str], vendors: dict[str, str]) -> dict:
    row = dict(host)
    evidence = []
    mac = str(row.get('mac') or '')
    local_mac = bool(MAC.fullmatch(mac) and int(mac[:2], 16) & 2)
    row['mac_locally_administered'] = local_mac
    if local_mac:
        row['vendor'] = ''
        evidence.append('Locally administered MAC; may be private/randomized. Vendor lookup skipped.')
    elif MAC.fullmatch(mac):
        prefix = mac.replace(':', '')[:6].upper()
        row['vendor'] = row.get('vendor') or vendors.get(prefix, '')
        if row['vendor']:
            evidence.append('MAC vendor is an interface manufacturer hint, not a device model.')
    else:
        row['vendor'] = ''
    name = str(row.get('hostname') or '').casefold()
    candidates = {kind for kind, hints in TYPE_HINTS.items()
                  if any(re.search(r'(^|[.\-_])' + re.escape(hint) + r'($|[.\-_0-9])', name)
                         for hint in hints)}
    gateway = row.get('ip') in gateway_ips
    if gateway:
        candidates.add('Router / gateway')
        evidence.append("Address is the scanner's configured default gateway; this identifies a network role only.")
    row['device_type'] = next(iter(candidates)) if len(candidates) == 1 else 'Unknown'
    row['confidence'] = ('Medium' if gateway else 'Low') if len(candidates) == 1 else 'Unknown'
    if name and candidates - ({'Router / gateway'} if gateway else set()):
        evidence.append('Device-type hint from hostname; names can be changed or spoofed.')
    if len(candidates) > 1:
        evidence.append('Conflicting device-type hints; classification withheld.')
    if not candidates:
        evidence.append('Insufficient evidence to classify this device.')
    row['model'] = 'Unknown'
    row['identification_evidence'] = evidence
    return row


def enrich(hosts: list[dict]) -> list[dict]:
    """At most 32 name lookups per range, 8 at once, one second each."""
    if not hosts:
        return []
    gateway_ips, vendors = gateways(), oui_vendors()
    pending = [host['ip'] for host in hosts if not host.get('hostname')][:32]
    with ThreadPoolExecutor(max_workers=8) as pool:
        names = dict(zip(pending, pool.map(hostname_for, pending)))
    rows = []
    for host in hosts:
        row = dict(host)
        row['hostname'] = row.get('hostname') or names.get(row['ip'], '')
        row['hostname_lookup'] = ('Available' if row['hostname'] else
                                  'No result' if row['ip'] in names else 'Limit reached')
        rows.append(classify(row, gateway_ips, vendors))
    return rows
