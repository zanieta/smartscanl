"""Manual discovery. Disabled until a server administrator approves ranges."""
import logging
import os
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from db.models import DiscoveryRun
from db.session import engine
from scanner.discovery import approved_networks, discover

log = logging.getLogger(__name__)
LOCK_ID = 847291035


def now():
    return datetime.now(timezone.utc).isoformat()


def enqueue(bind=engine) -> str | None:
    if os.getenv("NETWORK_DISCOVERY_ENABLED", "0") != "1":
        raise ValueError("Discovery is disabled. Configure approved ranges on the server first.")
    networks = approved_networks(os.getenv("NETWORK_DISCOVERY_CIDRS", ""))
    with bind.connect() as connection:
        locked = connection.execute(text("SELECT pg_try_advisory_xact_lock(:key)"),
                                    {"key": LOCK_ID}).scalar_one()
        if not locked:
            connection.rollback()
            return None
        with Session(bind=connection) as session:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            active = session.query(DiscoveryRun).filter(DiscoveryRun.status.in_(["queued", "running"]))
            active.filter(DiscoveryRun.started_at < cutoff).update(
                {"status": "interrupted", "finished_at": now()}, synchronize_session=False)
            if active.filter(DiscoveryRun.started_at >= cutoff).first():
                connection.rollback()
                return None
            run_id = str(uuid.uuid4())
            session.add(DiscoveryRun(id=run_id, started_at=now(), status="queued",
                                     networks=[str(n) for n in networks], hosts=[]))
            session.flush()
            connection.commit()
            return run_id


def run(bind=engine, run_id: str | None = None) -> int:
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
                row = session.get(DiscoveryRun, run_id) if run_id else None
                if run_id and (row is None or row.status != "queued"):
                    return 1
                if row is None:
                    row = DiscoveryRun(id=str(uuid.uuid4()), started_at=now(), status="running",
                                       networks=[str(n) for n in networks], hosts=[])
                    session.add(row)
                else:
                    # Do not scan a scope which changed since the admin clicked.
                    if row.networks != [str(n) for n in networks]:
                        row.status = "failed"
                        row.error = "Approved ranges changed. Start a new discovery run."
                        row.finished_at = now()
                        session.commit()
                        return 1
                    row.status = "running"
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
    import argparse
    parser = argparse.ArgumentParser(description="Manual approved-network discovery")
    parser.add_argument("--manual", action="store_true", required=True,
                        help="Explicitly request one discovery run")
    parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    raise SystemExit(run())
