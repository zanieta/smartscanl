"""Bounded service observations and conservative, version-aware CVE reports."""
import ipaddress
import re
import subprocess
import uuid
from xml.etree import ElementTree

from db.models import CVE
from db.queries import find_cves
from reports.formatter import format_report_data


def service_scan(target: str) -> dict:
    target = str(ipaddress.IPv4Address(target))
    result = subprocess.run(['nmap', '--unprivileged', '-sT', '-sV', '--version-light',
        '-Pn', '-n', '--top-ports', '100', '--max-retries', '1', '--host-timeout', '45s',
        '-oX', '-', target], capture_output=True, check=True, timeout=60)
    if len(result.stdout) > 1_000_000:
        raise ValueError('Service scan output exceeds limit.')
    root = ElementTree.fromstring(result.stdout)
    host = next((h for h in root.findall('host')
                 if any(a.get('addr') == target for a in h.findall('address'))), None)
    if host is None or host.get('timedout') == 'true':
        raise ValueError('Device did not produce a complete service response.')
    services = []
    for port in host.findall('ports/port'):
        state, service = port.find('state'), port.find('service')
        if state is None or state.get('state') != 'open':
            continue
        if service is None:
            service = ElementTree.Element('service')
        services.append({'port': int(port.get('portid')), 'product': service.get('product', '')[:200],
            'version': service.get('version', '')[:100], 'service': service.get('name', '')[:100],
            'cpe': [(c.text or '')[:300] for c in service.findall('cpe')][:10]})
    return {'host': target, 'os': 'Unknown', 'services': services,
            'open_ports': [s['port'] for s in services]}


def cpe_identity(value: str):
    # Ignore escaped/ambiguous CPEs rather than infer a product from a banner.
    if not isinstance(value, str):
        return None
    parts = value.split(':')
    if value.startswith('cpe:/') and len(parts) == 5:
        fields = [parts[1][1:], *parts[2:]]
    elif value.startswith('cpe:2.3:') and len(parts) == 13 and all(p in ('*', '-') for p in parts[6:]):
        fields = parts[2:6]
    else:
        return None
    if fields[0] not in ('a', 'o', 'h') or any(not re.fullmatch(r'[A-Za-z0-9_.+-]{1,100}', p)
                                               or p == '-' for p in fields[1:]):
        return None
    return tuple(fields)


def assess(db, scan: dict) -> dict:
    identities = {}
    for service in scan.get('services', []):
        cpes = service.get('cpe') or []
        for cpe in ([cpes] if isinstance(cpes, str) else cpes):
            identity = cpe_identity(cpe)
            if identity:
                identities.setdefault(identity, []).append(service['port'])
    findings = {}
    database_ready = db.query(CVE.cve_id).first() is not None
    for (part, vendor, product, version), ports in list(identities.items())[:20]:
        for cve in find_cves(db, vendor, product, version=version, part=part):
            if cve.get('match_status') != 'version_match':
                continue
            cve = dict(cve)
            cve['fix'] = (f'Check the {vendor}/{product} vendor advisory for {cve["cve_id"]}; '
                f'verify applicability to observed version {version}, then back up and apply the '
                'vendor-supported fix. Restrict access to affected services until remediation and rescan afterward.')
            cve['match_reason'] += f' Service CPE observed on TCP ports {sorted(set(ports))}; vendor={vendor}, product={product}.'
            findings.setdefault(cve['cve_id'], cve)
    report = format_report_data(str(uuid.uuid4()), scan, list(findings.values()), {'findings': []})
    coverage = ('CVE database is empty; vulnerability assessment unavailable.' if not database_ready else
        'No supported explicit versioned service CPE; vulnerability assessment unavailable.' if not identities else
        'Checked versioned service CPEs against the local CVE database; database freshness and vendor applicability still require review.')
    report['coverage'] = coverage
    report['assessment_status'] = 'assessed' if database_ready and identities else 'not_assessed'
    report['summary'] += ' ' + coverage + ' Limited to the top 100 TCP ports and at most 20 product identities; no exploit or credential tests. Recommendations are deterministic, not AI-generated.'
    report['identity_count'] = min(len(identities), 20)
    return report
