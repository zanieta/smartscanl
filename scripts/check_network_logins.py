"""Manual batch audits: all discovered hosts, reviewed profiles, no guessing."""
import logging
import os
import time
import uuid

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.models import DeviceAudit, NetworkScanRun, _now
from db.session import engine
from scanner import device_audit as audit

LOCK_ID = 847291036
MAX_SECONDS = 900
MAX_ATTEMPTS = 3


def latest_scan(db):
    return db.query(NetworkScanRun).filter(NetworkScanRun.status.in_(['completed', 'partial'])).order_by(
        NetworkScanRun.started_at.desc()).first()


def enqueue(scan_id, operator_id, bind=engine):
    if os.getenv('DEVICE_AUDIT_ENABLED', '0') != '1':
        raise ValueError('Device auditing is disabled.')
    audit.profiles()  # Fail before queuing if administrator configuration is invalid.
    with bind.begin() as connection:
        if not connection.execute(text('SELECT pg_try_advisory_xact_lock(:key)'), {'key': LOCK_ID}).scalar_one():
            return None
        with Session(bind=connection) as db:
            source = latest_scan(db)
            if source is None or source.id != scan_id:
                raise ValueError('Refresh results and use the latest completed subnet scan.')
            targets = sorted({h['ip'] for h in source.results if h.get('ip')})
            if not targets or len(targets) > 1024:
                raise ValueError('No discovered devices or invalid discovery size.')
            for target in targets:
                audit.validate_target(target)
            # A crash leaves the batch blocked, rather than silently starting another.
            rows = db.query(DeviceAudit).filter_by(action='login-batch').all()
            if any(r.result.get('status') in ('queued', 'running') for r in rows):
                return None
            key = 'login-batch:' + str(uuid.uuid4())
            db.add(DeviceAudit(key=key, target=scan_id, action='login-batch', operator_id=operator_id,
                created_at=_now(), result={'status': 'queued', 'targets': targets, 'results': []}))
            db.flush()
            return key


def check_device(target, operator_id, profiles, bind=engine):
    if os.getenv('DEVICE_AUDIT_ENABLED', '0') != '1':
        raise ValueError('Device auditing disabled.')
    audit.validate_target(target)
    with Session(bind) as db:
        row = DeviceAudit(key=f'check-default:{target}', target=target, action='check-default',
            operator_id=operator_id, created_at=_now(), result={'status': 'running', 'attempts': []})
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return {'target': target, 'status': 'already_checked', 'attempts': [],
                'reason': 'Previously checked or reserved, including older one-attempt checks. No further login sent.'}
        attempts = []
        result = {'status': 'unsupported', 'reason': 'No configured reviewed credential profile matches the observed model.'}
        try:
            identity = audit.identify(target)
            model = identity.get('model', 'Unknown')
            seen = set()
            for profile in profiles:
                if model == 'Unknown' or profile.model != model:
                    continue
                credentials = (os.getenv(profile.username_env), os.getenv(profile.password_env))
                if not all(credentials) or credentials in seen:
                    continue
                seen.add(credentials)
                if len(attempts) >= MAX_ATTEMPTS:
                    break
                if os.getenv('DEVICE_AUDIT_ENABLED', '0') != '1':
                    raise ValueError('Auditing disabled.')
                audit.validate_target(target)
                # Reserve each slot durably before the request. Never retry after a crash.
                attempts.append({'profile_id': profile.id, 'username': credentials[0],
                    'credential_sent': None, 'status': 'reserved'})
                row.result = {'status': 'running', 'attempts': list(attempts)}
                db.commit()
                result = audit.check_default(target, profile)
                attempts[-1] = {**attempts[-1], **result}
                row.result = {**result, 'attempts': list(attempts)}
                db.commit()
                if result['status'] != 'tested_credentials_rejected':
                    break
        except Exception:
            result = {'status': 'inconclusive', 'reason': 'Identity, connection, certificate or scope validation failed. Stopped without retry.'}
        label, recommendation = audit.LOGIN_RESULTS.get(result['status'], audit.LOGIN_RESULTS['inconclusive'])
        row.result = {**result, 'attempts': attempts, 'label': label, 'recommendation': recommendation}
        db.commit()
        logging.getLogger(__name__).info('Batch device check target=%s admin=%s status=%s slots=%s',
            target, operator_id, result['status'], len(attempts))
        return {'target': target, **row.result}


def run(key, bind=engine):
    started = time.monotonic()
    with bind.connect() as connection:
        if not connection.execute(text('SELECT pg_try_advisory_lock(:key)'), {'key': LOCK_ID}).scalar_one():
            connection.rollback()
            return
        connection.commit()
        try:
            with Session(bind=connection) as db:
                row = db.get(DeviceAudit, key)
                if row is None or row.result.get('status') != 'queued':
                    return
                data = {**row.result, 'status': 'running'}
                row.result = data
                db.commit()
                try:
                    profiles = audit.profiles()
                    for target in data['targets']:
                        if time.monotonic() - started >= MAX_SECONDS:
                            outcome = {'target': target, 'status': 'not_checked', 'reason': 'Batch time limit reached.'}
                        elif os.getenv('DEVICE_AUDIT_ENABLED', '0') != '1':
                            outcome = {'target': target, 'status': 'not_checked', 'reason': 'Device auditing disabled.'}
                        else:
                            try:
                                outcome = check_device(target, row.operator_id, profiles, bind)
                            except ValueError:
                                outcome = {'target': target, 'status': 'not_checked', 'reason': 'Device is no longer in approved scope.'}
                        data = {**data, 'results': [*data['results'], outcome]}
                        row.result = data
                        db.commit()
                    row.result = {**data, 'status': 'completed', 'finished_at': _now()}
                except Exception:
                    db.rollback()
                    row = db.get(DeviceAudit, key)
                    row.result = {**data, 'status': 'interrupted', 'reason': 'Batch stopped. Reserved devices will not be retried.'}
                db.commit()
        finally:
            connection.rollback()
            connection.execute(text('SELECT pg_advisory_unlock(:key)'), {'key': LOCK_ID})
            connection.commit()
