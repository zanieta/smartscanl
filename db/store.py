"""CRUD/helpers for accounts, clients, scan tokens, and persisted scans.

Kept separate from queries.py (which is CVE-matching) so the scanning domain and
the account/token domain don't bleed into each other.
"""
import json
import secrets

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import User, Client, ScanToken, TokenUsage, Scan


# ===================== users =====================

def list_users(db: Session) -> list:
    return db.query(User).order_by(User.created_at.desc()).all()

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


# ===================== clients =====================

def create_client(db: Session, name: str, contact: str = None, notes: str = None) -> Client:
    client = Client(name=name.strip(), contact=(contact or None), notes=(notes or None))
    db.add(client)
    db.commit()
    db.refresh(client)
    return client

def list_clients(db: Session) -> list:
    return db.query(Client).order_by(Client.name.asc()).all()

def get_client(db: Session, client_id: int):
    return db.query(Client).filter(Client.id == client_id).first()


# ===================== tokens =====================

def _gen_token_value(db: Session) -> str:
    """A readable, unique token like 'VS-7F3A-9KQ2'."""
    while True:
        a = secrets.token_hex(2).upper()
        b = secrets.token_hex(2).upper()
        value = f"VS-{a}-{b}"
        if not db.query(ScanToken).filter(ScanToken.token == value).first():
            return value

def generate_token(db: Session, client_id: int, scan_limit: int, created_by: int = None) -> ScanToken:
    token = ScanToken(
        token=_gen_token_value(db),
        client_id=client_id,
        scan_limit=max(1, int(scan_limit)),
        uses=0,
        is_active=True,
        created_by=created_by,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return token

def list_tokens(db: Session) -> list:
    return db.query(ScanToken).order_by(ScanToken.created_at.desc()).all()

def get_token_by_value(db: Session, value: str):
    if not value:
        return None
    return db.query(ScanToken).filter(ScanToken.token == value.strip()).first()

def revoke_token(db: Session, token_id: int) -> None:
    tok = db.query(ScanToken).filter(ScanToken.id == token_id).first()
    if tok:
        tok.is_active = False
        db.commit()

def consume_token(db: Session, token: ScanToken, operator_id: int,
                  target: str, scan_id: str, scan_type: str) -> None:
    """Spend one use of a token and record who spent it on what."""
    token.uses = (token.uses or 0) + 1
    db.add(TokenUsage(
        token_id=token.id,
        operator_id=operator_id,
        target=target,
        scan_id=scan_id,
        scan_type=scan_type,
    ))
    db.commit()

def token_usage(db: Session, token_id: int) -> list:
    return (db.query(TokenUsage)
            .filter(TokenUsage.token_id == token_id)
            .order_by(TokenUsage.created_at.desc())
            .all())


# ===================== scans =====================

def persist_scan(db: Session, report: dict, scan_type: str,
                 client_id: int = None, operator_id: int = None,
                 target: str = None) -> None:
    """Save a finished scan. The full report dict goes in payload so the
    report/PDF renderers can be hydrated back verbatim."""
    db.add(Scan(
        scan_id=report["scan_id"],
        scan_type=scan_type,
        client_id=client_id,
        operator_id=operator_id,
        target=target or report.get("host") or report.get("url"),
        summary=(report.get("summary") or "")[:2000],
        critical_count=report.get("critical_count", 0),
        high_count=report.get("high_count", 0),
        cves_found=report.get("cves_found", 0),
        payload=json.dumps(report),
        created_at=report.get("created_at"),
    ))
    db.commit()

def delete_scan(db: Session, scan_id: str) -> bool:
    """Hard-delete a persisted scan. Returns True if a row was removed, False
    if no scan with that id existed."""
    row = db.get(Scan, scan_id)
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


def load_payloads(db: Session, scan_type: str) -> dict:
    """scan_id -> report dict, for rehydrating the in-memory caches on startup."""
    out = {}
    rows = (db.query(Scan)
            .filter(Scan.scan_type == scan_type)
            .order_by(Scan.created_at.asc())
            .all())
    for row in rows:
        try:
            out[row.scan_id] = json.loads(row.payload)
        except (TypeError, ValueError):
            continue
    return out

def scans_by_client(db: Session) -> list:
    """Per-client rollup for the dashboard: counts + severity totals + last scan."""
    rows = (db.query(
                Client.id, Client.name,
                func.count(Scan.scan_id).label("scan_count"),
                func.coalesce(func.sum(Scan.critical_count), 0).label("critical_total"),
                func.coalesce(func.sum(Scan.high_count), 0).label("high_total"),
                func.max(Scan.created_at).label("last_scanned"),
            )
            .outerjoin(Scan, Scan.client_id == Client.id)
            .group_by(Client.id, Client.name)
            .order_by(Client.name.asc())
            .all())
    return [{
        "client_id": r.id,
        "client": r.name,
        "scan_count": r.scan_count or 0,
        "critical_total": int(r.critical_total or 0),
        "high_total": int(r.high_total or 0),
        "last_scanned": r.last_scanned,
    } for r in rows]
