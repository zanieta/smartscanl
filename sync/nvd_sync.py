import os
import time
import httpx
import argparse
import re
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from db.session import SessionLocal, init_db
from db.models import CVE, CPEMatch, SyncLog

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def parse_cpe_23(cpe_str: str) -> dict:
    # Example: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    if not isinstance(cpe_str, str):
        return None
    parts = re.split(r"(?<!\\):", cpe_str)
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return {
            "part": parts[2],
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5] if len(parts) > 5 and parts[5] != "*" else None
        }
    return None


def iter_cpe_matches(node: dict, context_required: bool = False):
    context_required = context_required or bool(node.get('negate')) or node.get('operator') == 'AND'
    for match in node.get('cpeMatch', []):
        criteria = dict(match)
        parts = re.split(r"(?<!\\):", str(match.get('criteria', '')))
        criteria['context_required'] = context_required or any(
            value not in ('*', '') for value in parts[6:]
        )
        yield criteria
    for child in node.get('nodes', []) + node.get('children', []):
        yield from iter_cpe_matches(child, context_required)

def fetch_cves_page(start_index: int, extra_params: dict | None = None) -> dict:
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {
        "startIndex": start_index,
        "resultsPerPage": 2000
    }
    if extra_params:
        params.update(extra_params)

    # NVD API key limit: 50 req / 30 sec (0.6s per req). Without: 5 req / 30 sec (6.0s)
    sleep_time = 0.7 if NVD_API_KEY else 6.1
    time.sleep(sleep_time)

    with httpx.Client(timeout=30.0) as client:
        response = client.get(NVD_URL, headers=headers, params=params)
        response.raise_for_status()
        return response.json()

def extract_cvss(metrics: dict) -> tuple:
    # Prefer V3.1 > V4.0 > V3.0 > V2
    if "cvssMetricV31" in metrics:
        data = metrics["cvssMetricV31"][0]["cvssData"]
        return data.get("baseScore"), data.get("baseSeverity", "MEDIUM"), "3.1"
    elif "cvssMetricV40" in metrics:
        data = metrics["cvssMetricV40"][0]["cvssData"]
        return data.get("baseScore"), data.get("baseSeverity", "MEDIUM"), "4.0"
    elif "cvssMetricV30" in metrics:
        data = metrics["cvssMetricV30"][0]["cvssData"]
        return data.get("baseScore"), data.get("baseSeverity", "MEDIUM"), "3.0"
    elif "cvssMetricV2" in metrics:
        data = metrics["cvssMetricV2"][0]["cvssData"]
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "MEDIUM")
        return data.get("baseScore"), severity, "2.0"
    return None, "UNKNOWN", None

def _upsert_cve(db: Session, cve_data: dict, added: int, updated: int) -> tuple[int, int]:
    cve_id = cve_data.get("id")
    if not cve_id:
        return added, updated

    # Get Description
    desc = "No description available."
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value")
            break

    # Get CVSS
    cvss_score, severity, cvss_version = extract_cvss(cve_data.get("metrics", {}))

    published = cve_data.get("published")
    last_modified = cve_data.get("lastModified")

    # Check if exists
    existing_cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if existing_cve:
        legacy = db.query(CPEMatch.id).filter(
            CPEMatch.cve_id == cve_id, CPEMatch.match_criteria.is_(None)
        ).first()
        if existing_cve.last_modified == last_modified and not legacy:
            return added, updated  # unchanged

        existing_cve.description = desc
        existing_cve.cvss_score = cvss_score
        existing_cve.severity = severity
        existing_cve.cvss_version = cvss_version
        existing_cve.last_modified = last_modified

        # Delete old CPEs
        db.query(CPEMatch).filter(CPEMatch.cve_id == cve_id).delete()
        updated += 1
    else:
        new_cve = CVE(
            cve_id=cve_id,
            description=desc,
            cvss_score=cvss_score,
            severity=severity,
            cvss_version=cvss_version,
            published=published,
            last_modified=last_modified
        )
        db.add(new_cve)
        added += 1

    # Extract CPEs
    configurations = cve_data.get("configurations", [])
    for config in configurations:
        for match in iter_cpe_matches(config):
            parsed = parse_cpe_23(match.get("criteria"))
            if not parsed:
                continue
            db.add(CPEMatch(
                cve_id=cve_id,
                part=parsed["part"],
                vendor=parsed["vendor"],
                product=parsed["product"],
                version=parsed["version"],
                version_start=match.get("versionStartIncluding") or match.get("versionStartExcluding"),
                version_end=match.get("versionEndExcluding") or match.get("versionEndIncluding"),
                match_criteria=match,
            ))

    return added, updated

def sync_cves(db: Session, max_pages: int = None):
    init_db()
    
    start_time = datetime.now(timezone.utc).isoformat()
    log = SyncLog(feed="ALL", started_at=start_time, status="running")
    db.add(log)
    db.commit()

    start_index = 0
    total_results = 1 # temporary
    added = 0
    updated = 0
    
    print(f"Starting full NVD sync...")

    try:
        page_count = 0
        while start_index < total_results:
            if max_pages and page_count >= max_pages:
                print(f"Reached max pages ({max_pages}), stopping early.")
                break
                
            print(f"Fetching page starting at {start_index}...")
            data = fetch_cves_page(start_index)
            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                break
                
            for item in vulnerabilities:
                added, updated = _upsert_cve(db, item.get("cve", {}), added, updated)

            db.commit()
            start_index += len(vulnerabilities)
            page_count += 1
            print(f"Progress: {start_index} / {total_results}")

        log.finished_at = datetime.now(timezone.utc).isoformat()
        log.status = "success"
        log.records_added = added
        log.records_updated = updated
        log.last_modified_cursor = start_time
        db.commit()
        print(f"Sync complete! Added: {added}, Updated: {updated}")

    except Exception as e:
        db.rollback()
        log.status = f"failed: {str(e)}"
        log.finished_at = datetime.now(timezone.utc).isoformat()
        db.commit()
        print(f"Sync failed: {e}")

def latest_cursor(db: Session):
    """Most recent successful sync's cursor, or None if never synced."""
    log = (db.query(SyncLog)
             .filter(SyncLog.status == "success",
                     SyncLog.last_modified_cursor.isnot(None))
             .order_by(SyncLog.id.desc()).first())
    return log.last_modified_cursor if log else None


MAX_CURSOR_AGE_DAYS = 120  # NVD rejects lastModStartDate windows over 120 days


def sync_cves_since(db: Session) -> None:
    """Incremental sync: pull only CVEs modified since the last cursor.
    Falls back to a full sync on the very first run (no cursor yet), or if
    the cursor is too stale for NVD's 120-day lastModStartDate window."""
    init_db()
    cursor = latest_cursor(db)
    if not cursor:
        print("No cursor yet — running full sync.")
        return sync_cves(db)

    now = datetime.now(timezone.utc)

    try:
        cursor_dt = datetime.fromisoformat(cursor)
    except ValueError:
        cursor_dt = None

    if cursor_dt is None or (now - cursor_dt) > timedelta(days=MAX_CURSOR_AGE_DAYS):
        print("Cursor missing or older than 120 days — running full sync instead.")
        return sync_cves(db)

    start_time = now.isoformat()
    log = SyncLog(feed="INCREMENTAL", started_at=start_time, status="running")
    db.add(log)
    db.commit()

    extra = {"lastModStartDate": cursor,
             "lastModEndDate": start_time}
    start_index = 0
    total_results = 1
    added = updated = 0

    try:
        while start_index < total_results:
            data = fetch_cves_page(start_index, extra_params=extra)
            total_results = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            for item in vulns:
                added, updated = _upsert_cve(db, item.get("cve", {}), added, updated)
            db.commit()
            start_index += len(vulns)

        log.status = "success"
        log.finished_at = datetime.now(timezone.utc).isoformat()
        log.records_added = added
        log.records_updated = updated
        log.last_modified_cursor = start_time  # advance ONLY on success
        db.commit()
        print(f"Incremental sync done: +{added} ~{updated}")
    except Exception:
        db.rollback()
        log.status = "failed"
        log.finished_at = datetime.now(timezone.utc).isoformat()
        db.commit()
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NVD CVE Sync")
    parser.add_argument("--full", action="store_true", help="Run full sync")
    parser.add_argument("--since", action="store_true",
                        help="Incremental sync (only CVEs modified since last cursor)")
    parser.add_argument("--pages", type=int, help="Max pages to pull (for testing)")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        if args.since:
            sync_cves_since(db)
        else:
            sync_cves(db, max_pages=args.pages)
    finally:
        db.close()
