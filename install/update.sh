#!/usr/bin/env bash
# Apply a reviewed release to the standard /opt/vulnsense installation.
set -euo pipefail
# Do not let the invoking shell redirect Python imports, dotenv interpolation,
# migrations, or libpq away from the installed configuration.
if [[ "${VULNSENSE_UPDATE_CLEAN_ENV:-}" != 1 ]]; then
    exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        HOME=/root VULNSENSE_UPDATE_CLEAN_ENV=1 /bin/bash "$0" "$@"
fi
umask 077

die() { printf '[update] ERROR: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 1 ]] || die "Usage: sudo bash install/update.sh /path/to/extracted-release"
[[ $(id -u) -eq 0 ]] || die "Run as root."
APP=/opt/vulnsense
SOURCE=$(realpath -e -- "$1")
[[ "$SOURCE" != "$APP" && "$SOURCE" != "$APP/"* ]] || die "Extract the release outside $APP."
[[ -f "$SOURCE/VERSION" && -f "$SOURCE/main.py" && -f "$SOURCE/requirements.txt" ]] || die "Expected an extracted release with VERSION, main.py and requirements.txt."
[[ -f "$APP/.env" && -x "$APP/.venv/bin/python" ]] || die "Existing installation not found; use setup.sh first."
for command in flock rsync tar pg_dump pg_restore curl systemctl nginx runuser; do
    command -v "$command" >/dev/null || die "Missing command: $command"
done
exec 9>/run/lock/vulnsense-update.lock
flock -n 9 || die "Another update is running."
nginx -t
systemctl is-active --quiet vulnsense.service || die "App must be running before an update."
systemctl is-active --quiet vulnsense-sync.service && die "CVE sync is running; wait for it to finish."

BACKUP=$(mktemp -d /var/backups/vulnsense-update-XXXXXXXX)
TIMER_ACTIVE=0
systemctl is-active --quiet vulnsense-sync.timer && TIMER_ACTIVE=1
STOPPED=0
CHANGED=0
SUCCESS=0
finish() {
    local status=$?
    if [[ $SUCCESS -eq 0 ]]; then
        printf '[update] Failed. Backup directory: %s\n' "$BACKUP" >&2
        if [[ $CHANGED -eq 1 ]]; then
            systemctl stop vulnsense-sync.timer || true
            systemctl stop vulnsense.service || true
            printf '[update] App and CVE timer left stopped. Review logs and restore before restarting.\n' >&2
        else
            if [[ $STOPPED -eq 1 ]]; then systemctl start vulnsense.service || true; fi
            if [[ $TIMER_ACTIVE -eq 1 ]]; then systemctl start vulnsense-sync.timer || true; fi
        fi
    fi
    return "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
systemctl stop vulnsense-sync.timer
# Recheck after stopping the timer to catch a sync that started during preflight.
systemctl is-active --quiet vulnsense-sync.service && die "CVE sync started during preflight; retry when complete."
systemctl stop vulnsense.service
STOPPED=1

printf '[update] Backing up application, settings and database to %s\n' "$BACKUP"
# Includes the old virtualenv and .env; root-only backup may contain sensitive data.
tar -czf "$BACKUP/application.tar.gz" -C "$APP" .
tar -czf "$BACKUP/system-config.tar.gz" -C / etc/nginx etc/systemd/system
# Parse dotenv as data, never execute settings as shell code or expose passwords
# in process arguments. pg_dump uses the exact configured database, not a guess.
"$APP/.venv/bin/python" - "$APP/.env" "$BACKUP/database.dump" <<'PY'
import os
import subprocess
import sys
from dotenv import dotenv_values
from sqlalchemy.engine import make_url

url = make_url(dotenv_values(sys.argv[1], interpolate=False)["DATABASE_URL"])
if url.get_backend_name() not in {"postgresql", "postgres"}:
    raise SystemExit("Only PostgreSQL is supported")
if not url.database or not url.host:
    raise SystemExit("DATABASE_URL must specify a database and host")
env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
env.update(PGHOST=url.host, PGPORT=str(url.port or 5432),
           PGDATABASE=url.database, PGUSER=url.username or "",
           PGPASSWORD=url.password or "", PGCONNECT_TIMEOUT="15")
# Preserve libpq TLS options when a remote database is configured.
for key, value in url.query.items():
    if key not in {"sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout"}:
        raise SystemExit(f"Unsupported database option for backup: {key}")
    env["PG" + key.upper()] = str(value)
subprocess.run(["pg_dump", "--no-password", "--format=custom", "--file", sys.argv[2]],
               env=env, check=True)
PY
pg_restore --list "$BACKUP/database.dump" >/dev/null

CHANGED=1
# No --delete: retain runtime files and old files for additive releases. A release
# that requires file removals needs a reviewed, explicit migration instead.
rsync -a --chown=vulnsense:vulnsense \
    --exclude='.env*' --exclude='.venv' --exclude='.git' \
    --exclude='__pycache__' --exclude='.pytest_cache' --exclude='logs' \
    --exclude='*.pdf' --exclude='*.db' --exclude='*.dump' \
    "$SOURCE/" "$APP/"
cd "$APP"
runuser -u vulnsense -- .venv/bin/python -m pip install -r requirements.txt
runuser -u vulnsense -- .venv/bin/python -c 'from db.session import init_db; init_db()'
runuser -u vulnsense -- .venv/bin/python -m scripts.add_2fa_columns
runuser -u vulnsense -- .venv/bin/python -m scripts.add_cpe_match_criteria
# Existing systemd and nginx configuration is intentionally not replaced.
systemctl start vulnsense.service
HEALTHY=0
for attempt in {1..30}; do
    if [[ $(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 http://127.0.0.1:8000/login || true) == 200 ]]; then
        HEALTHY=1
        break
    fi
    sleep 2
done
[[ $HEALTHY -eq 1 ]] || die "Login health check failed. See journalctl -u vulnsense."
systemctl is-active --quiet vulnsense.service || die "Service stopped after health check."
if [[ $TIMER_ACTIVE -eq 1 ]]; then systemctl start vulnsense-sync.timer; fi
SUCCESS=1
printf '[update] Complete. Settings and HTTPS preserved. Backup: %s\n' "$BACKUP"
printf '[update] Verify login and a report through your HTTPS URL. CVE refresh is a separate step; see INSTALL.md.\n'
