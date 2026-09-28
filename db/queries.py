from sqlalchemy.orm import Session
from .models import CVE, CPEMatch
from .versions import match_version

def os_to_target(os_string: str) -> tuple:
    """Helper to map common OS strings to NVD vendor/product tuples"""
    os_lower = os_string.lower()
    if "windows 11" in os_lower:
        return ("microsoft", "windows_11")
    elif "windows 10" in os_lower:
        return ("microsoft", "windows_10")
    elif "windows" in os_lower:
        return ("microsoft", "windows")
    elif "ubuntu" in os_lower:
        return ("canonical", "ubuntu_linux")
    elif "debian" in os_lower:
        return ("debian", "debian_linux")
    elif "linux" in os_lower:
        return ("linux", "linux_kernel")
    return ("unknown", "unknown")

def find_cves(db: Session, vendor: str, product: str, limit: int = 50,
              version: str | None = None) -> list:
    """Filter versions before limiting distinct CVEs; retain uncertain candidates."""
    vendor = vendor.lower()
    product = product.lower()
    if limit <= 0:
        return []
    
    results = db.query(CVE, CPEMatch).\
        join(CPEMatch, CVE.cve_id == CPEMatch.cve_id).\
        filter(CPEMatch.vendor == vendor, CPEMatch.product == product).\
        order_by(CVE.cvss_score.desc().nullslast(), CVE.cve_id).yield_per(500)
        
    # The CVE -> CPEMatch join repeats a CVE once per affected product; dedupe by id.
    candidates = {}
    for cve, match in results:
        if len(candidates) >= limit and cve.cve_id not in candidates:
            break
        status, reason = match_version(match, version)
        if status == 'excluded':
            continue
        if candidates.get(cve.cve_id, {}).get('match_status') == 'version_match':
            continue
        candidates[cve.cve_id] = {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "cvss_score": cve.cvss_score,
            "severity": cve.severity,
            "published_date": cve.published,
            "detected_version": version,
            "match_status": status,
            "match_reason": reason,
        }
    return list(candidates.values())[:max(0, limit)]
