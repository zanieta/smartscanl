"""Read the local, standard Ubuntu security pocket. Never update APT or install packages."""
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import json
from pathlib import Path
import platform
import re
import subprocess


def release_date(lists, series):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", series):
        return None
    dates = []
    for path in lists.glob(f"*_dists_{series}-security_InRelease"):
        with path.open("rb") as stream:
            header = stream.read(8192).decode("ascii", "replace").splitlines()
        if "Origin: Ubuntu" not in header or f"Suite: {series}-security" not in header:
            continue
        date = next((s[6:] for s in header if s.startswith("Date: ")), "")
        try:
            parsed = parsedate_to_datetime(date)
            if parsed.tzinfo is not None:
                dates.append(parsed.astimezone(timezone.utc))
        except (ValueError, OverflowError):
            continue
    return min(dates) if dates else None


def inventory(cache, compare, series, published, now):
    unknown = {"status":"not_assessed", "scope":"ubuntu-standard-security",
               "index_published_at":None, "count":None, "packages":[]}
    if published is None or published > now + timedelta(minutes=10):
        return unknown
    packages = []
    for pkg in cache:
        installed = pkg.installed
        if installed is None:
            continue
        best = None
        for version in pkg.versions:
            if compare(version.version, installed.version) <= 0:
                continue
            if not any(o.trusted and o.origin == "Ubuntu" and o.archive == series+"-security"
                       for o in version.origins):
                continue
            if best is None or compare(version.version, best) > 0:
                best = version.version
        if best is not None:
            packages.append({"package":pkg.name, "architecture":installed.architecture,
                             "installed":installed.version, "security_version":best})
    packages.sort(key=lambda row:(row["package"], row["architecture"]))
    return {"scope":unknown["scope"], "index_published_at":published.isoformat(),
            "status":"stale_index" if now-published > timedelta(days=7) else "observed",
            "count":len(packages), "packages":packages[:200],"truncated":len(packages)>200}


def local_updates():
    # python-apt belongs to Ubuntu's Python, not to the application's virtualenv.
    try:
        result = subprocess.run(["/usr/bin/python3", "-I", str(Path(__file__).resolve())],
                                capture_output=True, check=True, timeout=45,
                                env={"LC_ALL":"C", "PATH":"/usr/bin:/bin"})
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return {"status":"not_assessed","scope":"ubuntu-standard-security",
                "index_published_at":None,"count":None,"packages":[]}


if __name__ == "__main__":
    import apt
    import apt_pkg
    series = platform.freedesktop_os_release().get("VERSION_CODENAME", "")
    published = release_date(Path("/var/lib/apt/lists"), series)
    cache = apt.Cache(memonly=True)
    if not any(f.origin == "Ubuntu" and f.archive == series+"-security" and f.architecture == apt_pkg.config.find("APT::Architecture")
               for f in cache._cache.file_list):
        published = None
    print(json.dumps(inventory(cache, apt_pkg.version_compare, series,
                               published, datetime.now(timezone.utc))))
