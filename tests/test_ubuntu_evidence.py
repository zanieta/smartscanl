import subprocess
from types import SimpleNamespace

import pytest

from scanner import ubuntu_evidence as evidence


def test_partial_evidence(monkeypatch):
    monkeypatch.setattr(evidence.platform, "system", lambda: "Linux")
    monkeypatch.setattr(evidence.platform, "freedesktop_os_release", lambda: {"ID": "ubuntu"})
    values = {"/etc/machine-id": "a"*32, "/proc/sys/fs/protected_symlinks": "0",
              "/proc/sys/fs/protected_hardlinks": "unexpected-private-text"}
    monkeypatch.setattr(evidence, "_read", values.get)
    def query(args, **kwargs):
        assert args[0] == "/usr/bin/dpkg-query" and kwargs["timeout"] == 5
        return SimpleNamespace(returncode=1, stdout=b"nginx\tinstalled\t1.2-3\nlibc6\tconfig-files\t9\n")
    monkeypatch.setattr(evidence.subprocess, "run", query)
    report = evidence.collect()
    assert [v["status"] for v in report["controls"]] == ["deviation", "not_assessed"]
    assert "a"*32 not in str(report) and "unexpected-private-text" not in str(report)
    assert [p["name"] for p in report["packages"] if p["status"] == "observed"] == ["nginx"]


def test_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("fixed query", 5)
    monkeypatch.setattr(evidence.subprocess, "run", timeout)
    assert evidence.package_versions() == {}


def test_reject_other_os(monkeypatch):
    monkeypatch.setattr(evidence.platform, "system", lambda: "Other")
    with pytest.raises(ValueError, match="Ubuntu"):
        evidence.collect()
