"""Manual administrator-approved subnet workflow. No credential attempts."""
import ipaddress
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from db.models import DiscoveryRun, NetworkScanRun
from db.session import engine
from scanner.discovery import discover, selected_networks
from scanner.device_audit import identify
from scanner.identity_profiles import load_profiles
from scanner.network_assessment import assess, service_scan
from scripts.discover_network import LOCK_ID, now

MAX_HOSTS = 8
MAX_SECONDS = 900
log = logging.getLogger(__name__)


def reviewed_profile(profile_id):
    if not profile_id:
        return None
    profile = next((p for p in load_profiles() if p.id == profile_id), None)
    if profile is None:
        raise ValueError('Unknown reviewed identity profile.')
    return profile


def enqueue(networks, operator_id, profile_id='', bind=engine):
    scope = [str(n) for n in selected_networks(networks)]
    reviewed_profile(profile_id)
    with bind.connect() as connection:
        if not connection.execute(text('SELECT pg_try_advisory_xact_lock(:key)'), {'key': LOCK_ID}).scalar_one():
            return None
        with Session(bind=connection) as db:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
            active = db.query(NetworkScanRun).filter(NetworkScanRun.status.in_(['queued', 'running']))
            active.filter(NetworkScanRun.started_at < cutoff).update(
                {'status': 'interrupted', 'finished_at': now(), 'stage': 'interrupted'})
            discovery_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            if active.filter(NetworkScanRun.started_at >= cutoff).first() or db.query(DiscoveryRun).filter(
                    DiscoveryRun.status.in_(['queued', 'running']), DiscoveryRun.started_at >= discovery_cutoff).first():
                connection.rollback()
                return None
            run_id = str(uuid.uuid4())
            db.add(NetworkScanRun(id=run_id, started_at=now(), status='queued', stage='queued',
                networks=scope, operator_id=operator_id, profile_id=profile_id, results=[]))
            db.flush()
            connection.commit()
            return run_id


def run(run_id, bind=engine):
    started = time.monotonic()
    with bind.connect() as connection:
        if not connection.execute(text('SELECT pg_try_advisory_lock(:key)'), {'key': LOCK_ID}).scalar_one():
            connection.rollback()
            return
        connection.commit()
        try:
            with Session(bind=connection) as db:
                row = db.get(NetworkScanRun, run_id)
                if row is None or row.status != 'queued':
                    return
                try:
                    scope = selected_networks(row.networks)
                    profile = reviewed_profile(row.profile_id)
                    row.status, row.stage = 'running', 'discovering'
                    db.commit()
                    devices = {}
                    for subnet in scope:
                        selected_networks(row.networks)
                        for host in discover(subnet):
                            address = ipaddress.IPv4Address(host['ip'])
                            if address in subnet:
                                devices[str(address)] = host
                    row.results = [dict(host, state='pending') for host in devices.values()]
                    db.commit()
                    for index, item in enumerate(row.results):
                        results = list(row.results)
                        item = dict(item)
                        if index >= MAX_HOSTS or time.monotonic() - started >= MAX_SECONDS:
                            item.update(state='skipped', reason='Run safety limit reached; choose a smaller subnet to assess this device.')
                            results[index] = item
                            row.results = results
                            db.commit()
                            continue
                        selected_networks(row.networks)
                        row.stage = f'identifying {item["ip"]}'
                        db.commit()
                        identity = {'status': 'disabled', 'model': 'Unknown', 'firmware': 'Unknown'}
                        if os.getenv('DEVICE_AUDIT_ENABLED', '0') == '1':
                            try:
                                identity = identify(item['ip'], profile) if profile else identify(item['ip'])
                            except Exception:
                                identity = {'status': 'unavailable', 'model': 'Unknown', 'firmware': 'Unknown'}
                        item['identity'] = identity
                        row.stage = f'checking vulnerabilities {item["ip"]}'
                        db.commit()
                        try:
                            selected_networks(row.networks)
                            scan = service_scan(item['ip'])
                            row.stage = f'generating recommendations {item["ip"]}'
                            db.commit()
                            report = assess(db, scan)
                            report['created_at'] = now()
                            item.update(state=report['assessment_status'], report=report)
                        except Exception as exc:
                            item.update(state='failed', reason='Service assessment failed; this device was not fully assessed.')
                            log.warning('Network device assessment failed type=%s', type(exc).__name__)
                        results[index] = item
                        row.results = results
                        db.commit()
                    row.status = 'partial' if any(r['state'] != 'assessed' for r in row.results) else 'completed'
                    row.stage = 'finished'
                except Exception as exc:
                    db.rollback()
                    row = db.get(NetworkScanRun, run_id)
                    row.status, row.stage = 'failed', 'stopped'
                    row.error = 'Workflow stopped: verify approved scope, profile configuration and service logs. Retained results may be incomplete.'
                    log.warning('Network workflow failed type=%s', type(exc).__name__)
                row.finished_at = now()
                db.commit()
        finally:
            connection.execute(text('SELECT pg_advisory_unlock(:key)'), {'key': LOCK_ID})
            connection.commit()
