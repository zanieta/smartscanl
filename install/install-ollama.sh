#!/usr/bin/env bash
#
# install-ollama.sh — install the Ollama engine and pull the model VulnSense uses.
#
# Idempotent and safe to re-run. Runs standalone or is called by setup.sh.
# Run as root (or via sudo). Override the model with OLLAMA_MODEL=... if needed.
#
set -euo pipefail

OLLAMA_MODEL="${OLLAMA_MODEL:-gpt-oss:latest}"

log() { printf '\n\033[1;36m[ollama]\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m[ollama] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    die "Please run as root (sudo ./install-ollama.sh)."
fi

# 1. Engine ---------------------------------------------------------------------
if command -v ollama >/dev/null 2>&1; then
    log "Ollama already installed ($(ollama --version 2>/dev/null | head -1)); skipping engine install."
else
    log "Installing the Ollama engine via the official script..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

# 2. Service --------------------------------------------------------------------
# The official installer registers a systemd unit on most distros. Make sure it
# is enabled and running so the API is up before we pull.
if command -v systemctl >/dev/null 2>&1; then
    log "Enabling and starting the ollama service..."
    systemctl enable --now ollama || true
fi

# 3. Wait for the API -----------------------------------------------------------
log "Waiting for the Ollama API on 127.0.0.1:11434..."
for i in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
        break
    fi
    [ "$i" -eq 30 ] && die "Ollama API did not come up within ~60s."
    sleep 2
done

# 4. Model ----------------------------------------------------------------------
log "Pulling model '${OLLAMA_MODEL}' (this can be a large, multi-GB download)..."
ollama pull "${OLLAMA_MODEL}"

log "Done. Installed models:"
ollama list
