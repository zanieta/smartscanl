"""Interpret only allowlisted observations; do not infer CVEs from a package version."""
from hashlib import sha256
import json
import re

from db.inventory import identity
from scanner.ubuntu_evidence import CONTROLS, PROFILE


def review(report, client_id):
    if report.get("profile") != PROFILE:
        raise ValueError("Unsupported assessment profile.")
    host = identity("ubuntu", report.get("host"))
    installation = report.get("installation")
    identifiable = (isinstance(installation, str) and re.fullmatch("[a-f0-9]{64}", installation)
                    and host and client_id is not None)
    raw = report.get("controls")
    checks = []
    for name in CONTROLS:
        key = "fs." + name
        candidates = [c for c in raw if isinstance(c, dict) and c.get("id") == key] if isinstance(raw, list) else []
        sample = candidates[0] if len(candidates) == 1 else {}
        value = sample.get("observed")
        state = "not_assessed"
        if sample.get("expected") == "1":
            if value == "0" and sample.get("status") == "deviation":
                state = "open"
            elif value == "1" and sample.get("status") == "pass":
                state = "pass"
        case = sha256(json.dumps([client_id, host, installation, PROFILE, key]).encode()).hexdigest() if identifiable else None
        checks.append({"id": key, "case_id": case, "state": state, "expected": "1",
                       "observed": value if state != "not_assessed" else None})
    return {"scan_id": report["scan_id"], "observed_at": report.get("created_at"), "profile": PROFILE,
            "checks": checks, "counts": {s: sum(c["state"] == s for c in checks)
                                         for s in ("open", "pass", "not_assessed")}}
