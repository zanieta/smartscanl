"""Interpret only allowlisted observations; do not infer CVEs from a package version."""
from hashlib import sha256
from datetime import datetime
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


def retest(reviews):
    """Read-only comparison of an explicitly selected evidence sequence; never close a ticket."""
    if not 2 <= len(reviews) <= 16 or len({r["scan_id"] for r in reviews}) != len(reviews):
        raise ValueError("Select 2 to 16 different observations.")
    previous_time = None
    cases = {}
    for index, item in enumerate(reviews):
        try:
            at = datetime.fromisoformat(item["observed_at"])
        except (ValueError, TypeError):
            raise ValueError("An observation has no usable timestamp.") from None
        if at.utcoffset() is None or (previous_time and at <= previous_time):
            raise ValueError("Select observations in strictly increasing time order.")
        previous_time = at
        for c in item["checks"]:
            key = c["id"]
            if not c["case_id"] or (index and cases[key]["case_id"] != c["case_id"]):
                raise ValueError("Observations must identify the same organization, host, installation and policy.")
            case = cases.setdefault(key, {"id": key, "case_id": c["case_id"], "history": [], "ever_open": False,
                                         "last_measured": None})
            state = c["state"]
            if state == "not_assessed":
                outcome = "not_verified"
            elif state == "open":
                outcome = "reopened" if case["ever_open"] and case["last_measured"] == "pass" else "open"
                case["ever_open"] = True
            else:
                outcome = "verified_resolved" if case["ever_open"] else "pass"
            if state != "not_assessed":
                case["last_measured"] = state
            case["history"].append({"scan_id": item["scan_id"], "observed_at": item["observed_at"],
                                    "outcome": outcome})
    return {"controls": [{"id": c["id"], "case_id": c["case_id"], "outcome": c["history"][-1]["outcome"],
                          "history": c["history"]} for c in cases.values()]}
