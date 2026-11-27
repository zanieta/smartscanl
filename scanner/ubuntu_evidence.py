"""Read a small, fixed Ubuntu baseline on this machine. No network or privilege escalation."""
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
import platform
import re
import subprocess
from uuid import uuid4


PROFILE = "ubuntu-link-protection-v1"
CONTROLS = ("protected_symlinks", "protected_hardlinks")
PACKAGES = ("openssl", "openssh-server", "nginx", "postgresql", "libc6")


def _read(path):
    try:
        with Path(path).open("rb") as stream:
            return stream.read(128).decode("ascii").strip()
    except (OSError, UnicodeError):
        return None


def _installation():
    machine = _read("/etc/machine-id")
    if not machine or not re.fullmatch(r"[a-f0-9]{32}", machine) or machine == "0" * 32:
        return None
    return hmac.new(b"DE-Webnet Security360/Ubuntu assessment/v1", bytes.fromhex(machine),
                    hashlib.sha256).hexdigest()


def package_versions():
    try:
        result = subprocess.run(
            ["/usr/bin/dpkg-query", "-W", "-f=${Package}\t${db:Status-Status}\t${Version}\n", *PACKAGES],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired):
        return {}
    # dpkg returns 1 if some of the fixed names have no record. Keep only measured versions.
    versions = {}
    if result.returncode in (0, 1):
        for line in result.stdout.decode("ascii", errors="replace").splitlines():
            fields = line.split("\t")
            if (len(fields) == 3 and fields[0] in PACKAGES and fields[1] == "installed"
                    and re.fullmatch(r"[0-9][a-zA-Z0-9.:+~_-]{0,127}", fields[2])):
                versions[fields[0]] = fields[2]
    return versions


def collect():
    if platform.system() != "Linux" or platform.freedesktop_os_release().get("ID") != "ubuntu":
        raise ValueError("This collector requires Ubuntu.")
    controls = []
    for name in CONTROLS:
        measured = _read("/proc/sys/fs/" + name)
        status = {"1": "pass", "0": "deviation"}.get(measured, "not_assessed")
        controls.append({"id": "fs." + name, "expected": "1",
                         "observed": measured if status != "not_assessed" else None, "status": status})
    packages = package_versions()
    return {"scan_id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
            "profile": PROFILE, "host": platform.node(), "installation": _installation(),
            "summary": f"Ubuntu local baseline: {sum(c['status']=='deviation' for c in controls)} deviations; "
                       f"{sum(c['status']=='not_assessed' for c in controls)} controls not assessed.",
            "controls": controls, "packages": [{"name": p, "version": packages.get(p),
                "status": "observed" if p in packages else "not_assessed"} for p in PACKAGES]}
