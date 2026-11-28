import subprocess
from types import SimpleNamespace

import pytest

from scanner import ubuntu_evidence as evidence


def test_partial_evidence(monkeypatch):
    monkeypatch.setattr(evidence, "local_updates", lambda: {"status":"not_assessed","count":None})
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


def test_review_never_equates_missing_with_pass():
    from reports.ubuntu_review import review
    sample = {"id":"fs.protected_symlinks", "expected":"1", "observed":"0", "status":"deviation"}
    record = {"scan_id":"a","profile":evidence.PROFILE,"host":"ubuntu","installation":"b"*64,"controls":[sample]}
    a = review(record, 1)
    assert a["counts"] == {"open":1,"not_assessed":1,"pass":0}
    case = a["checks"][0]["case_id"]
    assert case and review({**record,"scan_id":"b"},1)["checks"][0]["case_id"] == case
    assert review(record,2)["checks"][0]["case_id"] != case
    assert review({**record,"installation":None},1)["checks"][0]["case_id"] is None
    for controls in ([sample,sample], [{**sample,"status":"pass"}], None, []):
        assert review({**record,"controls":controls},1)["counts"]["not_assessed"] == 2


def test_cached_security_updates_do_not_count_untrusted_or_nonsecurity():
    from datetime import datetime, timedelta, timezone
    from scanner.ubuntu_updates import inventory
    t = datetime.now(timezone.utc)
    def version(v, archive="noble-security", trusted=True):
        origin = SimpleNamespace(trusted=trusted, origin="Ubuntu", archive=archive)
        return SimpleNamespace(version=v, architecture="amd64", origins=[origin])
    package = SimpleNamespace(name="fixture", installed=version("1"),
        versions=[version("5","noble-updates"),version("4",trusted=False),version("2"),version("3")])
    def check(published):
        return inventory([package], lambda a,b:int(a)-int(b), "noble", published, t)
    result = check(t)
    assert result["status"]=="observed" and result["count"]==1
    assert result["packages"][0]["security_version"]=="3"
    assert check(t-timedelta(days=8))["status"]=="stale_index"
    assert check(None)["count"] is None and check(t+timedelta(days=1))["count"] is None


def test_security_index_date(tmp_path):
    from scanner.ubuntu_updates import release_date
    path = tmp_path / "mirror_dists_noble-security_InRelease"
    path.write_text("Origin: Ubuntu\nSuite: noble-security\nDate: Thu, 26 Nov 2026 12:00:00 UTC\n")
    assert release_date(tmp_path, "noble").year == 2026
    path.write_text("Origin: Example\nSuite: noble-security\nDate: Thu, 26 Nov 2026 12:00:00 UTC\n")
    assert release_date(tmp_path,"noble") is None
