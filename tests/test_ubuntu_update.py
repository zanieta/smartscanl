"""Execute the updater with fake services and a temporary app; never touch live data."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install"
if (INSTALL / "linux").is_dir():
    INSTALL = INSTALL / "linux"
pytestmark = pytest.mark.skipif(os.name == "nt" or not shutil.which("rsync"),
                                reason="Ubuntu shell integration tests")


@pytest.fixture
def updater(tmp_path):
    app = tmp_path / "app"
    release = tmp_path / "release"
    bin_dir = tmp_path / "bin"
    for directory in (app, release, bin_dir, app / ".venv/bin", app / "reports", app / "logs"):
        directory.mkdir(parents=True, exist_ok=True)
    (app / ".env").write_text("SESSION_SECRET=preserve-me\n")
    (app / "reports/customer.pdf").write_text("private report")
    (app / "logs/app.log").write_text("audit")
    (app / "old.py").write_text("old")
    for name in ("main.py", "requirements.txt", "VERSION"):
        (release / name).write_text("candidate")
    (release / ".env").write_text("must-not-copy")
    script = (INSTALL / "update.sh").read_text()
    script = script.replace("APP=/opt/vulnsense", f"APP={app}")
    script = script.replace("/run/lock/vulnsense-update.lock", str(tmp_path / "lock"))
    script = script.replace("/var/backups/vulnsense-update-XXXXXXXX", str(tmp_path / "backup-XXXXXXXX"))
    runner = tmp_path / "update.sh"
    runner.write_text(script)
    fake = '''#!/usr/bin/env bash
name=$(basename "$0")
echo "$name $*" >> "$CALLS"
case "$name" in
  id) echo 0 ;;
  systemctl)
    if [[ "$1" == start && "${*: -1}" == vulnsense-sync.timer && "${FAIL_AT:-}" == timer ]]; then
      exit 1
    fi
    if [[ "$1" == is-active && "${*: -1}" == vulnsense-sync.service ]]; then
      [[ "${FAIL_AT:-}" == sync ]]; exit $?
    fi ;;
  nginx) [[ "${FAIL_AT:-}" != nginx ]] ;;
  python) [[ "${FAIL_AT:-}" != backup ]] ;;
  runuser)
    if [[ "$*" == *" -I - "* ]]; then
      [[ "$1" == -u && "$2" == vulnsense && "${FAIL_AT:-}" != backup ]]; exit $?
    fi
    [[ "${FAIL_AT:-}" != migration || "$*" != *add_cpe_match_criteria* ]] ;;
  curl) if [[ "${FAIL_AT:-}" == health ]]; then echo 500; else echo 200; fi ;;
  rsync)
    args=()
    for arg in "$@"; do [[ "$arg" == --chown=* ]] || args+=("$arg"); done
    /usr/bin/rsync "${args[@]}" ;;
  tar|pg_dump|pg_restore|sleep) exit 0 ;;
esac
'''
    for name in ("id", "systemctl", "nginx", "runuser", "curl", "rsync", "tar", "pg_dump", "pg_restore", "sleep"):
        path = bin_dir / name
        path.write_text(fake)
        path.chmod(0o755)
    python = app / ".venv/bin/python"
    python.write_text(fake)
    python.chmod(0o755)

    def run(fail_at=""):
        env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}",
                   CALLS=str(tmp_path / "calls"), FAIL_AT=fail_at,
                   VULNSENSE_UPDATE_CLEAN_ENV="1")
        result = subprocess.run(["bash", str(runner), str(release)], env=env,
                                capture_output=True, text=True, timeout=15)
        return result, (tmp_path / "calls").read_text()
    return run, app, release


def test_update_preserves_settings_and_runtime_files(updater):
    run, app, _ = updater
    result, calls = run()
    assert result.returncode == 0, result.stderr
    assert (app / ".env").read_text() == "SESSION_SECRET=preserve-me\n"
    assert (app / "reports/customer.pdf").read_text() == "private report"
    assert (app / "logs/app.log").read_text() == "audit"
    assert (app / "main.py").read_text() == "candidate"
    assert calls.index("pg_restore") < calls.index("rsync")
    assert f"runuser -u vulnsense -- {app}/.venv/bin/python -I - {app}/.env" in calls
    assert calls.index("add_cpe_match_criteria") < calls.index("systemctl start vulnsense.service")
    assert "systemctl start vulnsense-sync.timer" in calls
    assert "systemctl disable --now vulnsense-discovery.timer" in calls
    assert "systemctl stop vulnsense-discovery.service" in calls
    assert "systemctl start vulnsense-discovery" not in calls


@pytest.mark.parametrize("failure", ["nginx", "sync", "backup"])
def test_pre_copy_failure_never_changes_app(updater, failure):
    run, app, _ = updater
    result, calls = run(failure)
    assert result.returncode != 0
    assert not (app / "main.py").exists()
    assert "rsync" not in calls
    if failure == "backup":
        assert "systemctl start vulnsense.service" in calls


@pytest.mark.parametrize("failure", ["migration", "health", "timer"])
def test_post_copy_failure_stops_app_and_keeps_timer_paused(updater, failure):
    run, _, _ = updater
    result, calls = run(failure)
    assert result.returncode != 0
    assert calls.strip().endswith("systemctl stop vulnsense.service")
    if failure != "timer":
        assert "systemctl start vulnsense-sync.timer" not in calls
    assert calls.strip().endswith("systemctl stop vulnsense-sync.timer\nsystemctl stop vulnsense.service")
    assert "left stopped" in result.stderr


def test_requires_release_marker(updater):
    run, _, release = updater
    (release / "VERSION").unlink()
    result, calls = run()
    assert result.returncode != 0
    assert "Expected an extracted release" in result.stderr
    assert "systemctl" not in calls


def test_update_clears_inherited_environment(tmp_path):
    """Exercise the real re-exec without giving it a release to deploy."""
    script = (INSTALL / "update.sh").read_text()
    preamble = script.split('die() {', 1)[0]
    runner = tmp_path / "clean.sh"
    runner.write_text(preamble + '\nprintf "%s|%s|%s" "${DATABASE_URL-unset}" "${PYTHONPATH-unset}" "$PATH"\n')
    env = dict(os.environ, DATABASE_URL="must-not-inherit", PYTHONPATH="must-not-inherit")
    env.pop("VULNSENSE_UPDATE_CLEAN_ENV", None)
    result = subprocess.run(["bash", str(runner)], env=env, capture_output=True,
                            text=True, check=True, timeout=10)
    assert result.stdout == "unset|unset|/usr/sbin:/usr/bin:/sbin:/bin"
