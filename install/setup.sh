#!/usr/bin/env bash
#
# setup.sh — full-stack VulnSense bring-up on a fresh Ubuntu server.
#
# Provisions: system deps (python venv, nmap, PostgreSQL, nginx), the app under
# /opt/vulnsense, a PostgreSQL role/db, a rendered .env, local Ollama + model,
# systemd services (app + weekly CVE sync), and an nginx reverse proxy.
#
# Run as root:   sudo ./install/linux/setup.sh
# Fresh installation only. Use update.sh for existing installations.
#
# Non-interactive overrides (export before running to skip prompts):
#   APP_HOST, NVD_API_KEY, ANTHROPIC_API_KEY, ADMIN_PASSWORD,
#   BREAKGLASS_PASSWORD, RUN_FULL_SYNC=yes|no
#
set -euo pipefail

# ---- Config (override via environment) ---------------------------------------
APP_DIR="${APP_DIR:-/opt/vulnsense}"
APP_USER="${APP_USER:-vulnsense}"
DB_NAME="${DB_NAME:-vulnsense}"
DB_USER="${DB_USER:-vulnsense}"
OLLAMA_MODEL="${OLLAMA_MODEL:-gpt-oss:latest}"

FORCE_ENV=""
[[ $# -eq 0 ]] || { echo 'setup.sh takes no arguments; use update.sh for an existing installation.' >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\n\033[1;32m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[setup]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[setup] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# requirements.txt and main.py both sit at the install root in either layout
# this script can run from: two levels under install/linux/ in the source
# tree, one level under install/ in the flattened distribution package that
# scripts/build_package.py emits. A fixed "../.." breaks the flattened
# layout (it lands one directory above the actual app), so this walks up
# from SCRIPT_DIR looking for both markers together, rather than assuming a
# directory count — requirements.txt alone is common enough that stopping on
# it could land on an unrelated Python project instead. Same pattern as
# Find-InstallRoot in install/windows/setup.ps1 / install-service.ps1 /
# register-tasks.ps1, kept equivalent on purpose so both platforms agree on
# how the install root is found.
find_install_root() {
    local dir="$1" i parent
    for ((i = 0; i < 4; i++)); do
        if [ -f "${dir}/requirements.txt" ] && [ -f "${dir}/main.py" ]; then
            (cd "${dir}" && pwd)
            return 0
        fi
        parent="$(dirname "${dir}")"
        [ "${parent}" = "${dir}" ] && break
        dir="${parent}"
    done
    die "could not locate the VulnSense install root above ${1} (looked for requirements.txt and main.py together within 4 parent directory levels)."
}
SRC_DIR="$(find_install_root "${SCRIPT_DIR}")"

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo $0)."
command -v apt-get >/dev/null 2>&1 || die "This installer targets Ubuntu/Debian (apt-get not found)."
[[ ! -f "${APP_DIR}/.env" ]] || die "Existing installation found. Use update.sh; setup.sh must not overwrite deployed settings or HTTPS."

# ---- Prompts (skipped when the matching env var is already set) ---------------
prompt() {  # prompt VAR "question" [silent]
    local __var="$1" __q="$2" __silent="${3:-}" __val
    # ${!__var+set} is true whenever __var is SET, even to an empty string —
    # unlike ${!__var:-}, which treats "set but blank" the same as unset. That
    # distinction matters here: NVD_API_KEY="" is documented ("blank = skip
    # CVE data for now") as a deliberate non-interactive choice, not an
    # unanswered question, and must not fall through to `read` with no TTY.
    if [ -n "${!__var+set}" ]; then return; fi
    if [ "$__silent" = "silent" ]; then read -rs -p "$__q" __val; echo
    else read -r -p "$__q" __val; fi
    printf -v "$__var" '%s' "$__val"
}

log "VulnSense installer — answer a few questions, then it runs unattended."
prompt APP_HOST            "Public hostname for this server (e.g. scan.example.com): "
prompt NVD_API_KEY         "NVD API key (blank = skip CVE data for now): "
prompt ADMIN_PASSWORD      "Password for the initial 'admin' account: " silent
prompt BREAKGLASS_PASSWORD "Password for the break-glass super-admin: " silent
[ -n "${APP_HOST}" ]        || die "APP_HOST is required (nginx server_name)."
[ -n "${ADMIN_PASSWORD}" ]  || die "ADMIN_PASSWORD is required."
[ -n "${BREAKGLASS_PASSWORD}" ] || die "BREAKGLASS_PASSWORD is required."
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
# RUN_FULL_SYNC is deliberately NOT defaulted here (unlike ANTHROPIC_API_KEY
# above): defaulting it to "" would erase the unset-vs-set-empty distinction
# before prompt() ever sees it, reintroducing the same raw-truthiness bug
# prompt() exists to avoid. prompt()'s own ${!__var+set} test is set -u-safe
# without a prior default.

# ---- Generated secrets --------------------------------------------------------
DB_PASS="$(openssl rand -hex 16)"
SESSION_SECRET="$(openssl rand -hex 32)"

# ---- 1. System packages -------------------------------------------------------
log "Installing system packages (python, nmap, PostgreSQL, nginx)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
    python3 python3-venv python3-dev build-essential libpq-dev \
    postgresql postgresql-contrib nginx nmap curl ca-certificates openssl rsync \
    sudo zstd certbot python3-certbot-nginx
# sudo: this script uses `sudo -u <user>` throughout (to drop to APP_USER and
# to the postgres role) but is not itself guaranteed present on a minimal
# Ubuntu image — only on full Ubuntu Server images, where it ships by
# default. zstd: install-ollama.sh's upstream installer (curl | sh from
# ollama.com) needs it to extract the .tar.zst release asset and fails with
# a raw "requires zstd" error otherwise. Both are the same class of bug as
# the missing rsync this installer originally shipped with: a dependency
# real enough to go unnoticed on a full image and break on a minimal one.

# ---- 2. App user + code -------------------------------------------------------
if ! id "${APP_USER}" >/dev/null 2>&1; then
    log "Creating system user '${APP_USER}'..."
    useradd --system --create-home --home-dir "/home/${APP_USER}" --shell /usr/sbin/nologin "${APP_USER}"
fi

log "Copying application code to ${APP_DIR}..."
mkdir -p "${APP_DIR}"
# Preserve an existing .env; never overwrite CVE DB dumps or the venv.
rsync -a \
    --exclude '.venv' --exclude '.git' --exclude '__pycache__' \
    --exclude '*.db' --exclude '.env' --exclude '.pytest_cache' \
    "${SRC_DIR}/" "${APP_DIR}/"
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

# ---- 3. Python virtualenv -----------------------------------------------------
log "Building the Python virtualenv and installing dependencies..."
sudo -u "${APP_USER}" bash -c "
    set -e
    cd '${APP_DIR}'
    python3 -m venv .venv
    ./.venv/bin/pip install --upgrade pip
    ./.venv/bin/pip install -r requirements.txt
"

# ---- 4. PostgreSQL role + database -------------------------------------------
log "Provisioning PostgreSQL role and database..."
systemctl enable --now postgresql
if [ -f "${APP_DIR}/.env" ] && [ -z "${FORCE_ENV}" ]; then
    if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
        die "The '${DB_USER}' PostgreSQL role does not exist. Restore the role before continuing."
    fi
    log "Reusing the existing database role password from .env."
else
    sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
    CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';
  ELSE
    ALTER ROLE ${DB_USER} PASSWORD '${DB_PASS}';
  END IF;
END \$\$;
SQL
fi
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
    sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}"
fi

# ---- 5. Render .env -----------------------------------------------------------
if [ -f "${APP_DIR}/.env" ] && [ -z "${FORCE_ENV}" ]; then
    die "An .env appeared during setup; stopping rather than replacing settings."
else
    log "Writing ${APP_DIR}/.env ..."
    cat > "${APP_DIR}/.env" <<ENV
# Generated by install/linux/setup.sh on $(date -Iseconds)
DATABASE_URL=postgresql+psycopg://${DB_USER}:${DB_PASS}@127.0.0.1:5432/${DB_NAME}
SESSION_SECRET=${SESSION_SECRET}
# Flip to 1 after enabling TLS (certbot). Keep 0 while serving plain HTTP.
COOKIE_SECURE=0

LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=${OLLAMA_MODEL}
OLLAMA_NUM_CTX=8192
OLLAMA_KEEP_ALIVE=0
OLLAMA_TIMEOUT=300

ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}

NVD_API_KEY=${NVD_API_KEY}

ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}
BREAKGLASS_USERNAME=dewebnetadmin
BREAKGLASS_PASSWORD=${BREAKGLASS_PASSWORD}

WEB_SCAN_ALLOW_PRIVATE=0
NETWORK_DISCOVERY_ENABLED=0
NETWORK_DISCOVERY_CIDRS=
ENV
    chown "${APP_USER}:${APP_USER}" "${APP_DIR}/.env"
    chmod 600 "${APP_DIR}/.env"
fi

# ---- 6. Ollama ----------------------------------------------------------------
log "Installing Ollama and pulling '${OLLAMA_MODEL}'..."
OLLAMA_MODEL="${OLLAMA_MODEL}" bash "${SCRIPT_DIR}/install-ollama.sh"

# ---- 7. Initialize schema -----------------------------------------------------
log "Creating database tables..."
sudo -u "${APP_USER}" bash -c "cd '${APP_DIR}' && ./.venv/bin/python -c 'from db.session import init_db; init_db()'"
sudo -u "${APP_USER}" bash -c "cd '${APP_DIR}' && ./.venv/bin/python -m scripts.add_2fa_columns"
sudo -u "${APP_USER}" bash -c "cd '${APP_DIR}' && ./.venv/bin/python -m scripts.add_cpe_match_criteria"

# ---- 8. Optional initial CVE sync (long) --------------------------------------
if [ -n "${NVD_API_KEY}" ]; then
    prompt RUN_FULL_SYNC "Run the initial full CVE sync now? It pulls ~316k records and can take a long time. [y/N] "
    case "${RUN_FULL_SYNC}" in
        y|Y|yes|YES)
            log "Running full NVD sync (this will take a while)..."
            sudo -u "${APP_USER}" bash -c "cd '${APP_DIR}' && ./.venv/bin/python -m sync.nvd_sync --full"
            ;;
        *) warn "Skipping initial sync. Run later: sudo -u ${APP_USER} bash -c 'cd ${APP_DIR} && ./.venv/bin/python -m sync.nvd_sync --full'" ;;
    esac
else
    warn "No NVD_API_KEY set — CVE data will be empty. Add it to ${APP_DIR}/.env and run the full sync."
fi

# ---- 9. systemd services ------------------------------------------------------
log "Installing systemd units (app + weekly CVE sync)..."
install -m 644 "${APP_DIR}/deploy/vulnsense.service"      /etc/systemd/system/vulnsense.service
install -m 644 "${APP_DIR}/deploy/vulnsense-sync.service" /etc/systemd/system/vulnsense-sync.service
install -m 644 "${APP_DIR}/deploy/vulnsense-sync.timer"   /etc/systemd/system/vulnsense-sync.timer
systemctl daemon-reload
systemctl enable --now vulnsense.service
systemctl enable --now vulnsense-sync.timer
install -m 644 "${APP_DIR}/deploy/vulnsense-discovery.service" /etc/systemd/system/vulnsense-discovery.service
install -m 644 "${APP_DIR}/deploy/vulnsense-discovery.timer" /etc/systemd/system/vulnsense-discovery.timer
systemctl daemon-reload
# Discovery is opt-in: install the units but do not enable the timer.

# ---- 10. nginx ----------------------------------------------------------------
log "Configuring nginx reverse proxy for ${APP_HOST}..."
sed "s/APP_HOST/${APP_HOST}/g" "${APP_DIR}/deploy/nginx-vulnsense.conf" \
    > /etc/nginx/sites-available/vulnsense
ln -sf /etc/nginx/sites-available/vulnsense /etc/nginx/sites-enabled/vulnsense
rm -f /etc/nginx/sites-enabled/default
nginx -t
# reload-or-restart, not reload: `reload` fails outright if nginx isn't
# already running (stopped to free port 80, a prior partial install, etc.),
# which is not this installer's business to assume away. Small hardening,
# not a bug fix — nginx is expected to be running at this point in a normal
# install.
systemctl reload-or-restart nginx

# ---- Done ---------------------------------------------------------------------
cat <<DONE

========================================================================
 VulnSense is installed and running.

  App service : systemctl status vulnsense
  Logs        : journalctl -u vulnsense -f
  URL (HTTP)  : http://${APP_HOST}/
  Login       : admin / (the password you set)  — 2FA enrollment on first login
                break-glass: dewebnetadmin (2FA-exempt)

 NEXT STEPS
  1. Enable TLS:   certbot --nginx -d ${APP_HOST}
  2. After TLS, set COOKIE_SECURE=1 in ${APP_DIR}/.env and:
                   systemctl restart vulnsense
  3. If you skipped it, run the initial CVE sync (see the note above).
========================================================================
DONE
