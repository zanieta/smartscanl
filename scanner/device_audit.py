"""Explicit device audit. No credential guessing, redirects, or TLS bypass."""
import ipaddress
import os
import re
import time
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel, ConfigDict, Field
from scanner.discovery import approved_networks


class LoginProfile(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=r'^[a-z0-9-]{1,64}$')
    model: str = Field(min_length=3, max_length=100)
    reviewed: bool = False
    source_url: str = Field(pattern=r'^https://', max_length=500)
    proof_path: str = Field(pattern=r'^/[A-Za-z0-9/_-]*$', max_length=150)
    proof_marker: str = Field(min_length=12, max_length=200)
    username_env: str = Field(pattern=r'^DEVICE_DEFAULT_[A-Z0-9_]+$')
    password_env: str = Field(pattern=r'^DEVICE_DEFAULT_[A-Z0-9_]+$')


def validate_target(target: str) -> str:
    if os.getenv('NETWORK_DISCOVERY_ENABLED', '0') != '1':
        raise ValueError('Discovery is disabled.')
    ip = ipaddress.IPv4Address(target)
    networks = approved_networks(os.getenv('NETWORK_DISCOVERY_CIDRS', ''))
    if not any(ip in n for n in networks):
        raise ValueError('Device must be inside the approved network ranges.')
    return str(ip)


def profiles() -> list[LoginProfile]:
    filename = os.getenv('DEVICE_AUDIT_PROFILE_FILE', '')
    if not filename:
        return []
    import json
    path = Path(filename)
    if path.stat().st_size > 100_000:
        raise ValueError('Device profile file exceeds size limit.')
    rows = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(rows, list) or len(rows) > 100:
        raise ValueError('Device profiles must be a list of at most 100 entries.')
    parsed = [LoginProfile.model_validate(row) for row in rows]
    if len({p.id for p in parsed}) != len(parsed):
        raise ValueError('Duplicate device profile IDs.')
    return [p for p in parsed if p.reviewed]


def read_page(target: str, path: str = '/', auth=None) -> tuple[int, str, str]:
    # Literal IP only, HTTPS only, no environment proxies/netrc, no redirects.
    started = time.monotonic()
    with requests.Session() as session:
        session.trust_env = False
        with session.get(f'https://{target}{path}', auth=auth, allow_redirects=False,
                         verify=os.getenv('DEVICE_AUDIT_CA_BUNDLE') or True,
                         timeout=(3, 2), stream=True) as response:
            data = bytearray()
            for chunk in response.iter_content(1024):
                data.extend(chunk)
                if len(data) > 65_536 or time.monotonic() - started > 10:
                    raise ValueError('Device response exceeds audit limits.')
            return response.status_code, data.decode('utf-8', errors='replace'), response.headers.get('WWW-Authenticate', '')[:500]


def extract_identity(html: str) -> dict:
    """Only explicit labeled fields, never title guesses or server versions."""
    soup = BeautifulSoup(html, 'html.parser')
    for node in soup(['script', 'style', 'noscript']):
        node.decompose()
    labels = {'manufacturer': {'manufacturer', 'device manufacturer'},
              'device_type': {'device type'},
              'model': {'model', 'model name', 'device model', 'model number'},
              'firmware': {'firmware', 'firmware version'}}
    values = {key: set() for key in labels}
    for field, names in labels.items():
        for node in soup.find_all(['meta', 'dt', 'th', 'td']):
            if node.name == 'meta':
                label = str(node.get('name', '')).strip().lower()
                value = str(node.get('content', '')).strip()
            else:
                label = node.get_text(' ', strip=True).strip(': ').lower()
                sibling = node.find_next_sibling(['dd', 'td'])
                value = sibling.get_text(' ', strip=True) if sibling else ''
            if label in names and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._()/+-]{0,99}', value):
                values[field].add(value)
    result = {key: next(iter(items)) if len(items) == 1 else 'Unknown' for key, items in values.items()}
    result['evidence'] = {key: ('Explicit field on HTTPS page; device-reported, not independently verified.'
                               if len(items) == 1 else 'Conflicting or unavailable explicit fields.')
                          for key, items in values.items()}
    return result


def identify(target: str, profile=None) -> dict:
    code, html, _ = read_page(target, profile.path if profile else '/')
    if code != 200:
        return {'status': 'unavailable', 'model': 'Unknown', 'firmware': 'Unknown'}
    if profile:
        from scanner.identity_profiles import extract
        return extract(html, profile)
    return {'status': 'observed', **extract_identity(html), 'source': '/',
            'confidence': 'Device-reported; not independently verified'}


def check_default(target: str, profile: LoginProfile) -> dict:
    if not profile.reviewed:
        return {'status': 'unsupported', 'reason': 'Profile has not been reviewed.'}
    identity = identify(target)
    if identity.get('model') != profile.model:
        return {'status': 'inconclusive', 'reason': 'Observed model does not match the reviewed profile.'}
    code, body, challenge = read_page(target, profile.proof_path)
    if code in (423, 429) or re.search(r'locked|lockout|too many|rate.limit', body, re.I):
        return {'status': 'inconclusive_lockout', 'reason': 'Possible lockout or rate limit; no credential sent.'}
    if code != 401 or not re.match(r'^Basic\s', challenge, re.I) or profile.proof_marker in body:
        return {'status': 'inconclusive', 'reason': 'Expected unauthenticated baseline was not established.'}
    username, password = os.getenv(profile.username_env), os.getenv(profile.password_env)
    if not username or not password:
        return {'status': 'unsupported', 'reason': 'Reviewed default credential is not configured.'}
    # Exactly one credential-bearing request. No retry, other passwords or schemes.
    code, body, _ = read_page(target, profile.proof_path, auth=(username, password))
    if code in (423, 429) or re.search(r'locked|lockout|too many|rate.limit', body, re.I):
        return {'status': 'inconclusive_lockout', 'reason': 'Device reported a lockout or rate limit; stopped.'}
    if code == 200 and profile.proof_marker in body:
        return {'status': 'default_credentials_accepted'}
    if code == 401:
        return {'status': 'tested_credentials_rejected', 'reason': 'This does not prove the password was changed.'}
    return {'status': 'inconclusive', 'reason': 'No unambiguous authenticated proof.'}
