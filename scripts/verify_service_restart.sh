#!/usr/bin/env bash
set -euo pipefail

service="${1:-vulnsense.service}"
health_url="${2:-http://127.0.0.1:8000/login}"

before="$(systemctl show "$service" -p MainPID --value)"
echo "before_pid=$before"
systemctl kill --kill-who=main -s SIGKILL "$service"

restarted=0
after=0
for _ in $(seq 1 20); do
    after="$(systemctl show "$service" -p MainPID --value)"
    if [[ "$after" != "0" && "$after" != "$before" ]] \
            && curl -fsS "$health_url" >/dev/null 2>&1; then
        restarted=1
        break
    fi
    sleep 1
done

echo "after_pid=$after"
echo "active=$(systemctl is-active "$service")"
if [[ "$restarted" -ne 1 ]]; then
    echo "automatic_restart=FAIL"
    exit 1
fi
echo "automatic_restart=PASS"
