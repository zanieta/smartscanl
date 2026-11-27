#!/usr/bin/env bash
# Ubuntu-only. Start a disposable, private-socket cluster; never use a configured DB.
set -euo pipefail
if [[ $(id -u) == 0 ]]; then echo "Run as an unprivileged OS user." >&2; exit 2; fi
cd "$(dirname "$0")/.."
if [[ ! -f db/models.py && -f ../db/models.py ]]; then cd ..; fi
[[ -f db/models.py ]] || { echo "Application checkout not found." >&2; exit 2; }
python_bin="${PYTHON_BIN:-python3}"
pgbin="$(pg_config --bindir)"
root="$(mktemp -d /tmp/security360-rehearsal.XXXXXXXX)"
cleanup() {
    "$pgbin/pg_ctl" -D "$root/pg" -m fast stop >/dev/null 2>&1 || true
    if [[ "$root" == /tmp/security360-rehearsal.* && -O "$root" ]]; then rm -rf -- "$root"; fi
}
trap cleanup EXIT
unset PGSERVICE PGOPTIONS DATABASE_URL PGPASSWORD
export PGHOST="$root" PGPORT=25439 PGUSER="$(id -un)"
"$pgbin/initdb" -D "$root/pg" --no-locale --encoding=UTF8 >/dev/null
"$pgbin/pg_ctl" -D "$root/pg" -l "$root/server.log" -o "-k $root -p $PGPORT -c listen_addresses='' -c unix_socket_permissions=0700" -w start >/dev/null
createdb original
createdb restored
export PYTHONDONTWRITEBYTECODE=1
PGDATABASE=original "$python_bin" - <<'PY'
from sqlalchemy import create_engine, text
from db.models import Base
engine=create_engine("postgresql+psycopg://")
with engine.begin() as c:
    legacy=[t for t in Base.metadata.sorted_tables if t.name not in {"assets","asset_observations","cve_context"}]
    Base.metadata.create_all(c,tables=legacy)
    c.execute(text("INSERT INTO clients (id,name) VALUES (1,'fixture')"))
    c.execute(text("""INSERT INTO scans (scan_id,scan_type,client_id,target,payload,created_at)
                      VALUES ('fixture','pc',1,'node.example','{"host":"node.example","findings":[]}','2026-01-01')"""))
PY
pg_dump -Fc -f "$root/backup.dump" original
pg_restore --exit-on-error --single-transaction -d restored "$root/backup.dump"
fingerprint() { psql -XAtq -d "$1" -c "SELECT md5(scan_id||scan_type||client_id::text||target||payload||created_at) FROM scans ORDER BY scan_id"; }
before="$(fingerprint original)"
[[ -n "$before" && "$before" == "$(fingerprint restored)" ]]
PGDATABASE=restored "$python_bin" - <<'PY'
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from db.models import Base,Asset,AssetObservation
from scripts.backfill_assets import backfill
engine=create_engine("postgresql+psycopg://")
Base.metadata.create_all(engine)
with Session(engine) as db:
    assert backfill(db)==(1,0)
    assert backfill(db)==(1,0)
    assert db.query(Asset).one().identity=="node.example"
    assert db.query(AssetObservation).one().scan_id=="fixture"
PY
[[ "$before" == "$(fingerprint restored)" ]]
echo "PASS: isolated dump/restore, additive upgrade, repeated backfill, original report checksum unchanged"

# The source suite has fixtures which rebuild tables. Restrict them to a new DB
# in this private cluster, never a developer or customer database.
if [[ -n "${SOURCE_CHECKOUT:-}" ]]; then
    createdb vulnsense_test
    export TEST_DATABASE_URL="postgresql+psycopg:///vulnsense_test?host=$PGHOST&port=$PGPORT"
    export DATABASE_URL="$TEST_DATABASE_URL" PYTHON_DOTENV_DISABLED=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
    cd "$SOURCE_CHECKOUT"
    suites=(tests/test_nvd_sync_incremental.py tests/test_update_cves.py tests/test_console_controls.py)
    suites+=(tests/test_customer_isolation.py tests/test_workspace_write_guards.py)
    "$python_bin" -m pytest -q -p no:cacheprovider "${suites[@]}"
fi
