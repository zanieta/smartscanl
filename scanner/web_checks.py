"""Passive web checks + banner->CVE mapping.

`parse_web_result` normalizes the raw scan (mirrors scanner/parser.py).
`run_passive_checks` applies the same rule set used in the sample report:
missing security headers, weak cookie flags, no HTTPS redirect, version-banner
disclosure, and TLS expiry.
`banner_to_targets` maps detected server software to (vendor, product) tuples
for the local CVE database (mirrors db/queries.os_to_target).
"""
import re
from typing import Dict, Any, List, Tuple

# Security headers we expect a hardened site to send: header -> (id, title, severity, fix)
_SECURITY_HEADERS = {
    "strict-transport-security": (
        "WEB-HSTS", "Missing HSTS header", "Medium",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
    ),
    "content-security-policy": (
        "WEB-CSP", "Missing Content-Security-Policy", "Medium",
        "Define a Content-Security-Policy to mitigate XSS and content injection.",
    ),
    "x-frame-options": (
        "WEB-XFO", "Missing X-Frame-Options", "Low",
        "Add 'X-Frame-Options: DENY' (or a CSP frame-ancestors directive) to prevent clickjacking.",
    ),
    "x-content-type-options": (
        "WEB-XCTO", "Missing X-Content-Type-Options", "Low",
        "Add 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing.",
    ),
    "referrer-policy": (
        "WEB-REFPOL", "Missing Referrer-Policy", "Low",
        "Add a 'Referrer-Policy' header (e.g. strict-origin-when-cross-origin) to limit referrer leakage.",
    ),
    "permissions-policy": (
        "WEB-PERMPOL", "Missing Permissions-Policy", "Low",
        "Add a 'Permissions-Policy' header to restrict access to browser features.",
    ),
}

# Server software name (from Server / X-Powered-By banners) -> (vendor, product) in NVD terms
_PRODUCT_MAP = {
    "php": ("php", "php"),
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openssl": ("openssl", "openssl"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "express": ("openjsf", "express"),
}

_BANNER_RE = re.compile(r"([A-Za-z][A-Za-z0-9_\-]*)\s*/\s*([0-9][0-9A-Za-z.\-]*)")
_PRODUCT_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(" + "|".join(map(re.escape, _PRODUCT_MAP)) + r")(?=$|[\s/;(),])",
    re.IGNORECASE,
)


def _parse_cookie(raw: str) -> Dict[str, Any]:
    """Parse a single Set-Cookie header into name + security flags."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else "unknown"
    lowered = [p.lower() for p in parts[1:]]
    samesite = None
    for p in parts[1:]:
        if p.lower().startswith("samesite="):
            samesite = p.split("=", 1)[1].strip()
    return {
        "name": name,
        "secure": "secure" in lowered,
        "httponly": "httponly" in lowered,
        "samesite": samesite,
    }


def parse_web_result(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize the raw scan dict into a clean structure for checks + report."""
    headers = raw.get("headers", {})
    cookies = [_parse_cookie(c) for c in raw.get("set_cookie", [])]
    return {
        "url": raw.get("input_url", "Unknown"),
        "final_url": raw.get("final_url", raw.get("input_url", "Unknown")),
        "host": raw.get("host", "Unknown"),
        "status_code": raw.get("status_code"),
        "https": raw.get("scheme") == "https",
        "server": headers.get("server", "Unknown"),
        "powered_by": headers.get("x-powered-by", ""),
        "redirects_to_https": raw.get("http_redirects_to_https"),
        "headers": headers,
        "cookies": cookies,
        "tls": raw.get("tls"),
    }


def run_passive_checks(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Apply the passive rule set. Returns a list of finding dicts."""
    findings: List[Dict[str, Any]] = []
    headers = parsed.get("headers", {})

    # 1. Missing security headers
    for header, (cid, title, severity, fix) in _SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "id": cid, "title": title, "severity": severity,
                "evidence": f"Response did not include the '{header}' header.",
                "fix": fix, "category": "Security Header",
            })

    # 2. Cookie flags
    for cookie in parsed.get("cookies", []):
        name = cookie["name"]
        if parsed.get("https") and not cookie["secure"]:
            findings.append({
                "id": "WEB-COOKIE-SECURE", "title": f"Cookie '{name}' missing Secure flag",
                "severity": "Medium",
                "evidence": f"Set-Cookie for '{name}' has no Secure attribute on an HTTPS site.",
                "fix": f"Set the Secure attribute on the '{name}' cookie.",
                "category": "Cookie",
            })
        if not cookie["httponly"]:
            findings.append({
                "id": "WEB-COOKIE-HTTPONLY", "title": f"Cookie '{name}' missing HttpOnly flag",
                "severity": "Low",
                "evidence": f"Set-Cookie for '{name}' has no HttpOnly attribute (may be by design if JS must read it).",
                "fix": f"Set HttpOnly on '{name}' unless client-side JavaScript must read it.",
                "category": "Cookie",
            })
        if not cookie["samesite"]:
            findings.append({
                "id": "WEB-COOKIE-SAMESITE", "title": f"Cookie '{name}' missing SameSite attribute",
                "severity": "Low",
                "evidence": f"Set-Cookie for '{name}' has no SameSite attribute.",
                "fix": f"Set SameSite=Lax (or Strict) on the '{name}' cookie to reduce CSRF risk.",
                "category": "Cookie",
            })

    # 3. No HTTP -> HTTPS redirect
    if parsed.get("redirects_to_https") is False:
        findings.append({
            "id": "WEB-NO-HTTPS-REDIRECT", "title": "No HTTP-to-HTTPS redirect",
            "severity": "Medium",
            "evidence": "The plain-HTTP endpoint did not redirect to HTTPS.",
            "fix": "Force a 301 redirect from HTTP to HTTPS at the web server / edge.",
            "category": "Transport",
        })

    # 4. Version-banner disclosure
    for label, value in (("Server", parsed.get("server", "")), ("X-Powered-By", parsed.get("powered_by", ""))):
        if value and _BANNER_RE.search(value):
            findings.append({
                "id": "WEB-BANNER", "title": f"Software version disclosed via {label}",
                "severity": "Low",
                "evidence": f"{label}: {value}",
                "fix": f"Suppress or genericize the {label} banner so exact versions aren't exposed.",
                "category": "Info Disclosure",
            })

    # 5. TLS expiry
    tls = parsed.get("tls")
    if tls and tls.get("days_to_expiry") is not None:
        days = tls["days_to_expiry"]
        if days < 0:
            findings.append({
                "id": "WEB-TLS-EXPIRED", "title": "TLS certificate expired",
                "severity": "High",
                "evidence": f"Certificate expired {abs(days)} day(s) ago (notAfter: {tls.get('not_after')}).",
                "fix": "Renew and deploy a valid TLS certificate immediately.",
                "category": "TLS",
            })
        elif days < 30:
            findings.append({
                "id": "WEB-TLS-EXPIRING", "title": "TLS certificate expiring soon",
                "severity": "Medium",
                "evidence": f"Certificate expires in {days} day(s) (notAfter: {tls.get('not_after')}).",
                "fix": "Renew the TLS certificate before it expires.",
                "category": "TLS",
            })

    return findings


def banner_to_targets(parsed: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Map detected server software banners to (vendor, product) tuples for the local CVE DB."""
    targets: List[Tuple[str, str]] = []
    seen = set()
    banners = f"{parsed.get('server', '')} {parsed.get('powered_by', '')}"

    for match in _PRODUCT_RE.finditer(banners):
        name = match.group(1).lower()
        target = _PRODUCT_MAP.get(name)
        if target and target not in seen:
            seen.add(target)
            targets.append(target)

    # Framework fingerprint from cookies (e.g. Laravel)
    cookie_names = " ".join(c["name"].lower() for c in parsed.get("cookies", []))
    if "laravel_session" in cookie_names and ("laravel", "laravel") not in seen:
        seen.add(("laravel", "laravel"))
        targets.append(("laravel", "laravel"))

    return targets


def banner_version(parsed: dict, vendor: str, product: str) -> str | None:
    banners = f"{parsed.get('server', '')} {parsed.get('powered_by', '')}"
    versions = {match.group(2) for match in _BANNER_RE.finditer(banners)
                if _PRODUCT_MAP.get(match.group(1).lower()) == (vendor, product)}
    return next(iter(versions)) if len(versions) == 1 else None
