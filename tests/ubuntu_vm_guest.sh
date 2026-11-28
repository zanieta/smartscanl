#!/bin/bash
set -Eeuo pipefail
umask 077
mode=$1
[[ $(systemd-detect-virt) == kvm || $(systemd-detect-virt) == qemu ]]
[[ $(hostname) == security360-qa-* && ! -e /opt/vulnsense ]]
dir=/run/security360-qa
stage=prepare
say() { printf 'SECURITY360-QA %s %s\n' "$mode" "$*" >/dev/ttyS0; }
finish() {
    code=$?
    if ((code)); then
        say "FAIL at $stage (exit $code)"
        grep -E 'ERROR: (No matching distribution|Could not find a version)|Failed to fetch|Unable to locate package|curl: \([0-9]+\)|does not support|requires zstd' /root/qa-install.log | tail -5 >/dev/ttyS0 || true
    fi
    sync
    systemctl poweroff --no-block
}
trap finish EXIT
exec >/root/qa-install.log 2>&1
install -d /srv/candidate /srv/previous
tar xzf "$dir/candidate.tgz" -C /srv/candidate
tar xzf "$dir/previous.tgz" -C /srv/previous
base=/srv/candidate
if [[ $mode == upgrade ]]; then
    base=/srv/previous
    # The original unmodified RC9 expects the normal root login environment.
    export HOME=/root
    [[ $(cat "$base/VERSION") == 2026.10.20-rc9 ]]
fi
export APP_HOST=localhost NVD_API_KEY='' RUN_FULL_SYNC=no OLLAMA_MODEL=smollm2:135m
export ADMIN_PASSWORD=$(openssl rand -hex 24) BREAKGLASS_PASSWORD=$(openssl rand -hex 24)
stage=setup
say "starting unmodified setup.sh, version $(cat "$base/VERSION")"
timeout 1500 bash "$base/install/setup.sh" &
pid=$!
while kill -0 "$pid" 2>/dev/null; do
    sleep 12
    last=$(grep -E '\[setup\]|\[ollama\]' /root/qa-install.log | tail -1 | tr -cd '[:alnum:][:space:].:-' | tail -c 140 || true)
    say "setup: $last"
done
wait "$pid"
cd /opt/vulnsense
systemctl is-active --quiet vulnsense.service
curl --fail --silent --retry 15 --retry-all-errors --retry-delay 2 --max-time 5 http://localhost/login >/dev/null
if [[ $mode == upgrade ]]; then
    stage=preserve
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
        -addext subjectAltName=DNS:localhost -keyout /etc/ssl/private/qa.key -out /etc/ssl/certs/qa.crt
    chmod 600 /etc/ssl/private/qa.key
    sed -i '/listen 80;/a\    listen 443 ssl;\n    ssl_certificate /etc/ssl/certs/qa.crt;\n    ssl_certificate_key /etc/ssl/private/qa.key;' /etc/nginx/sites-available/vulnsense
    sed -i 's/^COOKIE_SECURE=0/COOKIE_SECURE=1/' .env
    nginx -t && systemctl reload nginx
    systemctl restart vulnsense
    runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d vulnsense -c "INSERT INTO clients(name) VALUES ('QA-upgrade-marker')"
    oldenv=$(sha256sum .env)
    oldproxy=$(sha256sum /etc/nginx/sites-available/vulnsense)
    stage=upgrade
    say "applying candidate update to installed RC9"
    timeout 600 bash /srv/candidate/install/update.sh /srv/candidate
    [[ $(sha256sum .env) == "$oldenv" && $(sha256sum /etc/nginx/sites-available/vulnsense) == "$oldproxy" ]]
    [[ $(runuser -u postgres -- psql -XAt -d vulnsense -c "SELECT count(*) FROM clients WHERE name='QA-upgrade-marker'") == 1 ]]
    backups=(/var/backups/vulnsense-update-*/database.dump)
    [[ ${#backups[@]} == 1 ]]
    runuser -u postgres -- createdb qa_restore
    runuser -u postgres -- pg_restore --exit-on-error --no-owner -d qa_restore <"${backups[0]}"
    [[ $(runuser -u postgres -- psql -XAt -d qa_restore -c "SELECT count(*) FROM clients WHERE name='QA-upgrade-marker'") == 1 ]]
    SSL_CERT_FILE=/etc/ssl/certs/qa.crt .venv/bin/python scripts/smoke_stack.py --env-file .env --base-url https://localhost
fi
stage=verify
cmp VERSION /srv/candidate/VERSION
for unit in postgresql nginx vulnsense.service vulnsense-sync.timer; do systemctl is-active --quiet "$unit"; done
nginx -t
curl -fsS --retry 10 --retry-all-errors http://localhost/login >/dev/null
runuser -u vulnsense -- .venv/bin/python -m scripts.ubuntu_evidence | .venv/bin/python -c 'import json,sys; r=json.load(sys.stdin); assert r["os"]["id"]=="ubuntu" and r["os"]["running_kernel"] and r["security_updates"]["status"] in {"observed","stale_index"}'
say "PASS installed version $(cat VERSION), database, Nginx, login, service, timer and collector"
