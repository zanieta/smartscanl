from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Float, ForeignKey, Boolean, Text, JSON
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _now() -> str:
    """UTC timestamp as a sortable ISO string (matches the SyncLog style)."""
    return datetime.now(timezone.utc).isoformat()

class CVE(Base):
    __tablename__ = "cves"
    
    cve_id = Column(String, primary_key=True)
    description = Column(String)
    cvss_score = Column(Float)
    severity = Column(String)
    cvss_version = Column(String)
    published = Column(String)
    last_modified = Column(String)
    source = Column(String, default="nvd")
    
    cpe_matches = relationship("CPEMatch", back_populates="cve", cascade="all, delete-orphan")

class CPEMatch(Base):
    __tablename__ = "cpe_matches"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, ForeignKey("cves.cve_id"), index=True)
    part = Column(String)
    vendor = Column(String, index=True)
    product = Column(String, index=True)
    version_start = Column(String, nullable=True)
    version_end = Column(String, nullable=True)
    version = Column(String, nullable=True)
    # NULL identifies legacy rows whose version boundaries were lossy.
    match_criteria = Column(JSON, nullable=True)
    
    cve = relationship("CVE", back_populates="cpe_matches")

class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id = Column(String, primary_key=True)
    started_at = Column(String, nullable=False, index=True)
    finished_at = Column(String, nullable=True)
    status = Column(String, nullable=False)
    networks = Column(JSON, nullable=False)
    hosts = Column(JSON, nullable=False)
    error = Column(String, nullable=True)


class SyncLog(Base):
    __tablename__ = "sync_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed = Column(String)
    started_at = Column(String)
    finished_at = Column(String)
    records_added = Column(Integer, default=0)
    records_updated = Column(Integer, default=0)
    status = Column(String)
    last_modified_cursor = Column(String)


# ===================== Accounts, clients, tokens, scans =====================

class User(Base):
    """A person who signs into the console. Accounts are created by an admin."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    email = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)   # pbkdf2 "algo$iters$salt$hash"
    role = Column(String, default="analyst")         # "admin" | "analyst"
    is_active = Column(Boolean, default=True)
    created_at = Column(String, default=_now)

    # --- two-factor auth (TOTP, RFC 6238) ---
    totp_secret = Column(String, nullable=True)      # base32; NULL = not yet enrolled
    totp_last_counter = Column(Integer, nullable=True)  # highest accepted 30s step (replay guard)
    totp_failures = Column(Integer, default=0)       # consecutive bad codes
    is_2fa_exempt = Column(Boolean, default=False)   # break-glass account only


class Client(Base):
    """A managed entity that scans roll up to. Tokens are issued per client."""
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, index=True, nullable=False)
    contact = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    created_at = Column(String, default=_now)

    tokens = relationship("ScanToken", back_populates="client", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="client")


class ScanToken(Base):
    """A floating scan credential issued to a client with an admin-set quota.

    A token is spendable until ``uses`` reaches ``scan_limit``; then it is
    exhausted and a new one must be generated. Each spend is recorded in
    TokenUsage so usage is attributable to the operator who ran the scan.
    """
    __tablename__ = "scan_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String, unique=True, index=True, nullable=False)
    client_id = Column(Integer, ForeignKey("clients.id"), index=True, nullable=False)
    scan_limit = Column(Integer, default=5)          # admin chooses the quota
    uses = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)        # admin can revoke early
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(String, default=_now)

    client = relationship("Client", back_populates="tokens")
    usages = relationship("TokenUsage", back_populates="token_ref", cascade="all, delete-orphan")

    @property
    def remaining(self) -> int:
        return max(0, (self.scan_limit or 0) - (self.uses or 0))

    @property
    def is_spendable(self) -> bool:
        return bool(self.is_active) and self.remaining > 0


class TokenUsage(Base):
    """One row per scan a token paid for — who ran it, against what, when."""
    __tablename__ = "token_usage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_id = Column(Integer, ForeignKey("scan_tokens.id"), index=True)
    operator_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    target = Column(String)
    scan_id = Column(String)
    scan_type = Column(String)                       # "pc" | "web"
    created_at = Column(String, default=_now)

    token_ref = relationship("ScanToken", back_populates="usages")


class Scan(Base):
    """Persisted scan so history and per-client rollups survive restarts.

    The full report dict is kept in ``payload`` (JSON text) so the existing
    report/PDF renderers can be hydrated straight back from the DB.
    """
    __tablename__ = "scans"

    scan_id = Column(String, primary_key=True)
    scan_type = Column(String, index=True)           # "pc" | "web"
    client_id = Column(Integer, ForeignKey("clients.id"), index=True, nullable=True)
    operator_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    target = Column(String)
    summary = Column(Text)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    cves_found = Column(Integer, default=0)
    payload = Column(Text)                           # full report JSON
    created_at = Column(String, default=_now, index=True)

    client = relationship("Client", back_populates="scans")
