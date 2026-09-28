"""Scheduled discovery. Disabled until a server administrator approves ranges."""
import logging
import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from db.models import DiscoveryRun
from db.session import engine
from scanner.discovery import approved_networks, discover

log = logging.getLogger(__name__)
LOCK_ID = 847291035


def now():
    return datetime.now(timezone.utc).isoformat()


def run(bind=engine) -> int:
    if os.getenv("NETWORK_DISCOVERY_ENABLED", "0") != "1":
        log.info("Network discovery disabled")
        return 0
    try:
        networks = approved_networks(os.getenv("NETWORK_DISCOVERY_CIDRS", ""))
    except ValueError as exc:
        log.error("Invalid discovery configuration: %s", exc)
        return 1
    with bind.connect() as connection:
        locked = connection.execute(text("SELECT pg_try_advisory_lock(:key)"),
                                    {"key": LOCK_ID}).scalar_one()
        connection.commit()
        if not locked:
            log.info("Discovery already running; skipped")
            return 0
        try:
            with Session(bind=connection) as session:
                # A previous process may have been interrupted; never present it as current.
                session.query(DiscoveryRun).filter_by(status="running").update(
                    {"status": "interrupted", "finished_at": now()})
                row = DiscoveryRun(id=str(uuid.uuid4()), started_at=now(), status="running",
                                   networks=[str(n) for n in networks], hosts=[])
                session.add(row)
                session.commit()
                try:
                    hosts = []
                    for network in networks:
                        hosts.extend(discover(network))
                    row.hosts = hosts
                    row.status = "completed"
                except Exception as exc:
                    row.status = "failed"
                    row.error = "Discovery failed; check service logs. No complete snapshot available."
                    log.error("Discovery failed (%s)", type(exc).__name__)
                row.finished_at = now()
                session.commit()
                # Bound history to 100 snapshots; this table contains only discovery data.
                old_ids = [r[0] for r in session.query(DiscoveryRun.id).order_by(
                    DiscoveryRun.started_at.desc()).offset(100).all()]
                if old_ids:
                    session.query(DiscoveryRun).filter(DiscoveryRun.id.in_(old_ids)).delete(
                        synchronize_session=False)
                    session.commit()
                log.info("Discovery run=%s status=%s hosts=%d", row.id, row.status, len(row.hosts))
                return 0 if row.status == "completed" else 1
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK_ID})
            connection.commit()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    raise SystemExit(run())
