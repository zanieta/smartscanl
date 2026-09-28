"""Scheduled CVE database updater.

Wraps sync.nvd_sync with staleness reporting, sync-mode selection, and exit
codes a scheduler can act on. Invoked weekly by the systemd timer on Linux and
by the "VulnSense CVE Sync" Scheduled Task on Windows.

    python -m scripts.update_cves               # sync now
    python -m scripts.update_cves --check-only  # report staleness, no network

Exit codes:
    0  sync succeeded, or --check-only and the data is fresh
    1  sync failed, or --check-only and the data is stale / never synced
"""
import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import sync.nvd_sync as nvd
from db.models import CVE, SyncLog
from db.session import SessionLocal

APP_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = APP_DIR / "logs"
DEFAULT_STALE_DAYS = 14.0

log = logging.getLogger("cve-update")


def configure_logging(log_dir: Path = LOG_DIR) -> None:
    """Log to the console and to a rotating logs/cve-update.log.

    A scheduled job has no terminal, so the file handler is the only durable
    record of what happened. Failure to create the directory is non-fatal —
    console output still reaches journalctl / the Task Scheduler history.
    """
    if log.handlers:
        return
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("[cve-update] %(message)s")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    log.addHandler(console)

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        rotating = RotatingFileHandler(
            log_dir / "cve-update.log", maxBytes=5 * 1024 * 1024, backupCount=3,
            encoding="utf-8")
        rotating.setFormatter(logging.Formatter(
            "%(asctime)s [cve-update] %(levelname)s %(message)s"))
        log.addHandler(rotating)
    except OSError as exc:
        log.warning("could not open %s (%s); logging to console only",
                    log_dir / "cve-update.log", exc)


def last_successful_sync(db) -> SyncLog | None:
    """Newest SyncLog row that actually finished successfully.

    Deliberately does NOT filter on `feed`: nvd_sync writes feed="ALL", and
    SyncLog has no other producer.
    """
    return (db.query(SyncLog)
              .filter(SyncLog.status == "success",
                      SyncLog.finished_at.isnot(None))
              .order_by(SyncLog.id.desc())
              .first())


def sync_age_days(db, now: datetime | None = None) -> float | None:
    """Days since the last successful sync finished, or None if never synced."""
    row = last_successful_sync(db)
    if row is None:
        return None
    finished = datetime.fromisoformat(row.finished_at)
    if finished.tzinfo is None:
        finished = finished.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return (now - finished).total_seconds() / 86400.0


def choose_mode(db) -> str:
    """'full' when there is nothing to build on, otherwise 'incremental'."""
    if last_successful_sync(db) is None:
        return "full"
    if db.query(CVE).count() == 0:
        return "full"
    return "incremental"


def run_update(db, mode: str) -> bool:
    """Run the sync and report whether it actually succeeded.

    sync_cves catches its own exceptions and returns normally after recording a
    "failed: ..." status, while sync_cves_since re-raises. Neither control flow
    is a reliable success signal, so the outcome is read back from SyncLog: a
    row newer than the one that existed before the run, with status 'success'.
    """
    previous = db.query(SyncLog).order_by(SyncLog.id.desc()).first()
    previous_id = previous.id if previous else 0

    if mode == "full":
        nvd.sync_cves(db)
    else:
        nvd.sync_cves_since(db)

    newest = db.query(SyncLog).order_by(SyncLog.id.desc()).first()
    if newest is None or newest.id == previous_id:
        log.error("sync produced no new log row — treating as failure")
        return False
    if newest.status != "success":
        log.error("sync finished with status %r", newest.status)
        return False
    log.info("+%s new  ~%s updated",
             newest.records_added or 0, newest.records_updated or 0)
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="update_cves",
        description="Sync the CVE database from NVD and report staleness.")
    parser.add_argument("--check-only", action="store_true",
                        help="Report staleness and exit; performs no network I/O.")
    parser.add_argument("--stale-days", type=float, default=DEFAULT_STALE_DAYS,
                        help=f"Age above which data is stale (default {DEFAULT_STALE_DAYS:g}).")
    args = parser.parse_args(argv)

    configure_logging()
    db = SessionLocal()
    try:
        age = sync_age_days(db)
        if age is None:
            log.warning("last successful sync: NEVER")
        else:
            state = "STALE" if age > args.stale_days else "fresh"
            log.info("last successful sync: %.1fd ago (%s, threshold %gd)",
                     age, state, args.stale_days)
        log.info("CVE rows: %s", f"{db.query(CVE).count():,}")

        if args.check_only:
            return 0 if (age is not None and age <= args.stale_days) else 1

        if not os.getenv("NVD_API_KEY"):
            log.warning(
                "NVD_API_KEY is not set — NVD throttles unkeyed clients to "
                "5 requests/30s (vs 50), so this sync will take roughly 10x "
                "longer. Get a free key at "
                "https://nvd.nist.gov/developers/request-an-api-key")

        mode = choose_mode(db)
        log.info("mode: %s", mode)
        try:
            ok = run_update(db, mode)
        except Exception as exc:                      # sync_cves_since re-raises
            log.error("sync raised: %s", exc)
            return 1
        if ok:
            log.info("OK")
            return 0
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
