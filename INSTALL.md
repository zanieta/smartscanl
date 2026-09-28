# VulnSense — Ubuntu installation

> **This repository is generated.** It is built from the VulnSense source tree
> and regenerated for each release — local commits here are overwritten by the
> next build. Report issues against the source repository.

Full-stack bring-up for a fresh Ubuntu/Debian server.

## Prerequisites

- Ubuntu 22.04+ (or Debian) with `sudo`/root
- `git` (to clone this repository — many minimal server images don't ship it;
  `sudo apt-get install -y git` if `git clone` below says "command not found")
- Internet access (apt, the Ollama install script, NVD, the model pull)
- A DNS name pointed at the box (for nginx `server_name` + TLS)

## Run

```bash
git clone <url> vulnsense && cd vulnsense
sudo ./install/setup.sh
```

Prefer a tarball over `git clone`? Download and extract
`smartscan-<version>-linux.tar.gz` from the release instead — it contains the
same `install/setup.sh` at the same path.

It will prompt for the public hostname, the `NVD_API_KEY`, and the admin /
break-glass passwords, then run unattended. To script it fully:

```bash
sudo APP_HOST=scan.example.com \
     NVD_API_KEY=xxxxxxxx \
     ADMIN_PASSWORD='...' \
     BREAKGLASS_PASSWORD='...' \
     RUN_FULL_SYNC=no \
     ./install/setup.sh
```

`setup.sh` is for a fresh installation only. It refuses an existing `.env`;
use the update command below instead. `--force-env` is no longer supported.

## Update an existing Ubuntu installation

This updater targets the standard `/opt/vulnsense` deployment with the
`vulnsense` system user and systemd units. Ubuntu 24.04 is the current test
environment; a clean-server installation still needs acceptance testing.

Download a reviewed release archive and verify its checksum from a trusted
release channel. Extract it outside `/opt/vulnsense`, then run **the updater
from that new release**, during a maintenance window:

```bash
cd /path/to/extracted-release
sudo bash install/update.sh "$PWD"
```

The updater locks out another updater, refuses an active scheduled CVE sync,
pauses its timer, stops the app, and creates a root-only backup directory under
`/var/backups`. It backs up the entire app (including settings and virtualenv),
Nginx/systemd configuration, and a PostgreSQL custom-format dump. Ensure disk
space for these backups. Dump readability is checked; this is not a restore drill.
Do not start manual syncs or other database writers during maintenance.

It then copies code without deleting runtime files, installs dependencies,
applies additive 2FA and CVE metadata migrations, starts the app, and checks
the local `/login` response. It restores the timer only if it was active before.
It does **not** change `.env`, Nginx/TLS, installed systemd units, the selected
model, or download CVEs. Releases requiring unit changes or removed files need
a separate reviewed migration. Test HTTPS login and a generated report afterward;
the local health check does not establish end-to-end readiness.

The updater clears inherited shell environment variables before running tools,
so a development `DATABASE_URL`, `PYTHONPATH`, or libpq setting cannot silently
redirect normal updates. Use a literal database URL in the installed `.env`;
shell-variable expressions in that URL are not supported by the backup step.

If an update fails after code changes, the app and timer stay stopped. The
printed backup directory contains `application.tar.gz`, `system-config.tar.gz`,
and `database.dump`. Review `journalctl -u vulnsense` first. Restore code and its
virtualenv together at the original path when rolling back. A database restore
can discard newer writes and must be separately approved; do not automatically
restore or drop the database. Keep backups protected and apply your retention
policy after a successful restore drill.

## Change settings

### Optional automatic network discovery

New installations include discovery units but leave the timer disabled. This is
active TCP host discovery, not passive monitoring or automatic vulnerability
scanning. Only use networks you are authorized to assess.

After upgrading an existing installation, install the new units explicitly:

```bash
sudo install -m 644 /opt/vulnsense/deploy/vulnsense-discovery.service /etc/systemd/system/
sudo install -m 644 /opt/vulnsense/deploy/vulnsense-discovery.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudoedit /opt/vulnsense/.env
```

Set `NETWORK_DISCOVERY_ENABLED=1` and `NETWORK_DISCOVERY_CIDRS` to your approved,
comma-separated RFC1918 IPv4 CIDRs. Maximum four non-overlapping ranges, each
/24 or smaller (1024 addresses total). Never assume a sample range is authorized.
Then:

```bash
sudo systemctl restart vulnsense
sudo systemctl enable --now vulnsense-discovery.timer
sudo systemctl start vulnsense-discovery.service
sudo journalctl -u vulnsense-discovery.service -n 30 --no-pager
```

Admins can view `/admin/network`. The timer checks approximately every 15 minutes
after the preceding run finishes. TCP probes to ports 80/443 can miss filtered
devices; absence is not proof that a device is offline. No root privileges,
service fingerprinting, LLM calls, or scan-token charges are used. Each range
has a 90-second timeout; an interrupted or failed run is not a complete inventory.
PostgreSQL prevents concurrent discovery jobs; the latest 100 snapshots are kept.
Invalid configuration fails before probes and is reported in the service journal.

Before application upgrades, stop the discovery timer and service, then restart
the timer only if it was previously enabled. To disable discovery permanently,
set `NETWORK_DISCOVERY_ENABLED=0`, stop/disable the timer, and restart the app.
The existing updater does not install or modify these systemd units automatically.

### Application settings

```bash
sudo cp -p /opt/vulnsense/.env /root/vulnsense-env-backup
sudo chmod 600 /root/vulnsense-env-backup
sudoedit /opt/vulnsense/.env
sudo systemctl restart vulnsense.service
sudo systemctl status vulnsense.service
```

Keep the existing database URL and session secret unless deliberately rotating
them. Set `LLM_PROVIDER=ollama` and the correct `OLLAMA_BASE_URL`/`OLLAMA_MODEL`
for Ollama, or `LLM_PROVIDER=claude` with valid API credentials and model access.
An available model tag alone does not prove successful report generation.
Use `COOKIE_SECURE=1` when HTTPS is configured. Never commit server `.env` files.

## Refresh the CVE database after this release

Existing CVE records need a **one-time full refresh** to populate lossless
version boundaries. A normal incremental update does not backfill unchanged
records. Historical reports are not rewritten. Run outside the app-update window:

```bash
# Confirm no other sync is running before starting; pause the timer.
sudo systemctl stop vulnsense-sync.timer
systemctl is-active vulnsense-sync.service
# Continue only if the sync service is inactive and no manual sync is running.
sudo -u vulnsense bash -c 'cd /opt/vulnsense && .venv/bin/python -m sync.nvd_sync --full'
sudo -u vulnsense bash -c 'cd /opt/vulnsense && .venv/bin/python -m scripts.update_cves --check-only'
sudo systemctl start vulnsense-sync.timer
```

Do not use a page limit for a complete refresh. On failure, inspect logs and
rerun the full refresh; incremental success alone does not establish backfill
completion. For routine incremental updates, use
`sudo systemctl start vulnsense-sync.service` and inspect its journal.

## What it installs

- **System packages:** `python3-venv`, build tools, `libpq-dev`, **nmap**,
  **PostgreSQL**, **nginx**, `curl`, `rsync`
- **App:** copied to `/opt/vulnsense`, owned by the `vulnsense` system user, with
  its own `.venv`
- **Database:** a `vulnsense` role + `vulnsense` database (password auto-generated)
- **`.env`:** rendered at `/opt/vulnsense/.env` (mode `600`) with a generated
  `SESSION_SECRET` and `DATABASE_URL`
- **Ollama:** engine + `gpt-oss:latest`, reachable at `127.0.0.1:11434`
- **systemd:** `vulnsense.service` (gunicorn/uvicorn on `:8000`) and the weekly
  `vulnsense-sync.timer` (incremental NVD sync)
- **nginx:** reverse proxy for your hostname → `127.0.0.1:8000`

These internal names — `/opt/vulnsense`, `vulnsense.service`,
`vulnsense-sync.timer`, the PostgreSQL role — are deliberately unchanged from
the source project. Only this repository and the release archive carry the
SmartScan name.

## After install

```bash
# 1. Enable HTTPS (rewrites the nginx block, adds 80->443 redirect):
sudo certbot --nginx -d scan.example.com

# 2. Turn on the Secure cookie flag now that TLS is in front:
sudo sed -i 's/^COOKIE_SECURE=0/COOKIE_SECURE=1/' /opt/vulnsense/.env
sudo systemctl restart vulnsense

# 3. If you deferred it, run the initial CVE sync (long — ~316k records):
sudo -u vulnsense bash -c 'cd /opt/vulnsense && set -a && . ./.env && set +a && \
  ./.venv/bin/python -m sync.nvd_sync --full'
```

## CVE updates

The weekly `vulnsense-sync.timer` runs an incremental sync automatically via
`scripts.update_cves`. To drive it by hand, `cd` into `/opt/vulnsense` first —
running the module from any other directory fails with `No module named
scripts`, because there's no `pyproject.toml`/`setup.py`: `scripts` is only
importable when `/opt/vulnsense` is on `sys.path` via the current working
directory. `deploy/vulnsense-sync.service` sets `WorkingDirectory=/opt/vulnsense`
for this same reason (it gets its environment separately, via
`EnvironmentFile=`).

```bash
sudo -u vulnsense bash -c 'cd /opt/vulnsense && ./.venv/bin/python -m scripts.update_cves'
sudo -u vulnsense bash -c 'cd /opt/vulnsense && ./.venv/bin/python -m scripts.update_cves --check-only'
systemctl list-timers vulnsense-sync
```

`--check-only` does no network I/O — it just reports how old the last
successful sync is (stale past 14 days by default) and exits non-zero if the
data is stale or has never synced. A blank `NVD_API_KEY` does not stop the
sync; it just makes NVD throttle the client roughly 10x harder (5 requests/30s
instead of 50), so a full sync takes much longer. Get a free key at
https://nvd.nist.gov/developers/request-an-api-key.

## Operate

```bash
systemctl status vulnsense           # app health
journalctl -u vulnsense -f           # live logs (incl. the [audit] trail)
systemctl list-timers vulnsense-sync # next weekly CVE sync
```

Log in as `admin` (2FA enrollment is forced on first login); `dewebnetadmin` is
the 2FA-exempt break-glass account for recovery.

## Verify the install

```bash
systemctl status vulnsense                                             # active (running)
curl -I http://localhost/                                              # HTTP response (a 200/302/401 all mean the app answered)
sudo -u vulnsense bash -c 'cd /opt/vulnsense && ./.venv/bin/python -m scripts.update_cves --check-only'
```

The last command should report a non-zero CVE row count and a sync age within
14 days once the initial sync has completed.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| CVE searches return nothing | `NVD_API_KEY` blank, sync never ran | Add the key to `/opt/vulnsense/.env`, run `sudo -u vulnsense bash -c 'cd /opt/vulnsense && ./.venv/bin/python -m scripts.update_cves'` |
| Scan fails at the analysis step | `OLLAMA_MODEL` tag absent on the Ollama host — this fails at scan time, not startup | `ollama list`, then `ollama pull gpt-oss:latest` |
| Logged out after re-running the installer | `.env` was regenerated | Restore the old `SESSION_SECRET`, or accept the new one |
| `nginx -t` fails | `APP_HOST` unset or wrong | Fix `server_name` in `/etc/nginx/sites-available/vulnsense` |
