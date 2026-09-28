"""Passive website scanner.

Fetches a URL the same way a browser would (one GET, following redirects) and
records only what the server volunteers: response headers, Set-Cookie headers,
the redirect behaviour, and the TLS certificate. No payloads are sent, nothing
is fuzzed -- this is the passive, non-intrusive half of web vuln scanning.

A light SSRF guard blocks private / loopback / link-local / cloud-metadata
targets by default (toggle with WEB_SCAN_ALLOW_PRIVATE=1) so the server can't be
abused to reach internal hosts.
"""
import os
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import httpx

USER_AGENT = "SmartScan/1.0 (passive-web-scanner)"
TIMEOUT = 20.0


def _normalize_url(url: str) -> str:
    """Ensure the URL has a scheme; default to https."""
    url = (url or "").strip()
    if not url:
        raise ValueError("No URL provided.")
    if "://" not in url:
        url = "https://" + url
    return url


def _host_is_blocked(host: str) -> bool:
    """Return True if the host resolves to a private / loopback / reserved IP.

    Resolution failures are treated as blocked (fail closed). Set
    WEB_SCAN_ALLOW_PRIVATE=1 to disable this guard for internal testing.
    """
    if os.getenv("WEB_SCAN_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes"):
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return True
    return False


def _get_tls_cert(host: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """Grab the TLS certificate for host:port. Returns None on any failure."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception:
        return None

    if not cert:
        return None

    def _join(field):
        # cert issuer/subject are tuples of ((key, value), ...)
        return ", ".join(f"{k}={v}" for rdn in field for (k, v) in rdn)

    not_after = cert.get("notAfter")
    days_to_expiry = None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_to_expiry = (exp - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    san = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]

    return {
        "issuer": _join(cert.get("issuer", [])),
        "subject": _join(cert.get("subject", [])),
        "not_before": cert.get("notBefore"),
        "not_after": not_after,
        "days_to_expiry": days_to_expiry,
        "san": san,
    }


def _check_http_redirect(host_url: str) -> Optional[bool]:
    """Check whether the plain-HTTP version redirects to HTTPS.

    Returns True/False, or None if it couldn't be determined.
    """
    parsed = urlparse(host_url)
    http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
    try:
        with httpx.Client(follow_redirects=False, timeout=TIMEOUT,
                          headers={"User-Agent": USER_AGENT}, verify=True) as client:
            resp = client.get(http_url)
    except httpx.HTTPError:
        return None
    if 300 <= resp.status_code < 400:
        location = resp.headers.get("location", "")
        return location.lower().startswith("https://")
    return False


def run_web_scan(url: str) -> Dict[str, Any]:
    """Passively scan a URL. Returns a raw dict of everything observed.

    Raises ValueError if the target is blocked by the SSRF guard, or
    httpx.HTTPError if the target can't be reached.
    """
    url = _normalize_url(url)
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Could not parse a hostname from '{url}'.")

    if _host_is_blocked(host):
        raise ValueError(
            f"Target '{host}' resolves to a private/reserved address and is blocked. "
            "Set WEB_SCAN_ALLOW_PRIVATE=1 to scan internal hosts."
        )

    with httpx.Client(follow_redirects=True, timeout=TIMEOUT,
                      headers={"User-Agent": USER_AGENT}, verify=True) as client:
        resp = client.get(url)

    final = urlparse(str(resp.url))

    # Lower-cased single-value header map (duplicates collapse; fine for our checks)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    set_cookie = resp.headers.get_list("set-cookie")
    redirect_chain = [str(r.url) for r in resp.history] + [str(resp.url)]

    tls = _get_tls_cert(host) if final.scheme == "https" else None

    return {
        "input_url": url,
        "final_url": str(resp.url),
        "scheme": final.scheme,
        "host": host,
        "status_code": resp.status_code,
        "headers": headers,
        "set_cookie": set_cookie,
        "redirect_chain": redirect_chain,
        "http_redirects_to_https": _check_http_redirect(url),
        "tls": tls,
    }
