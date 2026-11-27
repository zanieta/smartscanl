"""Project stored reports into organization-scoped inventory. Never contact an asset."""
from hashlib import sha256
from ipaddress import ip_address
import json
import re
from urllib.parse import urlsplit

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert

from .models import Asset, AssetObservation as Obs, Scan
from .store import client_scope


def identity(kind, raw):
    if not isinstance(raw, str) or len(raw)>4096 or any(ord(ch)<32 for ch in raw):
        return None
    try:
        site = urlsplit(raw) if kind == "web" else None
        if site and site.scheme not in {"https","http"}:
            return None
        host = (site.hostname if site else raw) or ""
        host = host.strip().rstrip(".").lower()
        if host in {"", "unknown"}:
            return None
        try:
            address = ip_address(host)
            host = f"[{address.compressed}]" if site and address.version==6 else address.compressed
        except ValueError:
            host = host.encode("idna").decode("ascii")
            if len(host)>253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                return None
        if not site:
            return host
        port = site.port
        default = 443 if site.scheme=="https" else 80
        return f"{site.scheme}://{host}" + (f":{port}" if port is not None and port!=default else "")
    except (ValueError, UnicodeError):
        return None


def project(db, scan, report):
    kind = scan.scan_type
    if kind not in {"pc","web"} or not isinstance(report,dict):
        return False
    key = identity(kind,report.get("url" if kind=="web" else "host") or scan.target)
    if key is None:
        return False
    asset_id = sha256(json.dumps([scan.client_id,kind,key]).encode()).hexdigest()
    db.execute(insert(Asset).values(id=asset_id,client_id=scan.client_id,kind=kind,identity=key,
                                    tags=[],exposure="unknown").on_conflict_do_nothing())
    def records(name):
        values = report.get(name)
        return [item for item in values if isinstance(item,dict)] if isinstance(values,list) else []
    def fields(item, keys):
        return {k:item[k] for k in keys if isinstance(item.get(k),(str,int,float))}
    services = [fields(s,("port","service","product","version","cpe")) for s in records("services")]
    sightings = records("findings")
    actionable = [f for f in sightings if f.get("match_status")!="uncertain" and
                  str(f.get("severity","")).lower() not in {"informational","none"}]
    findings = [fields(f,("cve_id","severity","detected_version","match_status","severity_source"))
                for f in actionable if f.get("cve_id")]
    uncertain = len(records("uncertain_findings"))+sum(f.get("match_status")=="uncertain" for f in sightings)
    db.execute(insert(Obs).values(scan_id=scan.scan_id,asset_id=asset_id,seen_at=scan.created_at,
                                  services=services,findings=findings,uncertain_count=uncertain).on_conflict_do_nothing())
    return True


def listed(db, user, after, limit):
    rows = (db.query(Asset,func.min(Obs.seen_at),func.max(Obs.seen_at),func.count(Obs.scan_id))
            .join(Obs).filter(client_scope(Asset.client_id,user),Asset.id>after)
            .group_by(Asset.id).order_by(Asset.id).limit(limit+1).all())
    return {"assets":[{"id":a.id,"client_id":a.client_id,"identity":a.identity,"kind":a.kind,"owner":a.owner,
                       "tags":a.tags,"exposure":a.exposure,"first_seen":first,"last_seen":last,"reports":n}
                      for a,first,last,n in rows[:limit]],"next":rows[limit-1][0].id if len(rows)>limit else None}
