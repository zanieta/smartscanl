"""Reference enrichment, not proof that any asset is exploitable."""
from datetime import date, datetime, timezone
import re
from urllib.parse import urlsplit

from sqlalchemy.dialects.postgresql import insert
from db.models import CVEContext

CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")


def nvd_context(db, record):
    refs = []
    for ref in record.get("references",[]):
        url = ref.get("url","")
        if "Vendor Advisory" not in (ref.get("tags") or []) or not isinstance(url,str):
            continue
        try:
            parts = urlsplit(url)
            if parts.scheme=="https" and parts.hostname and not parts.username and not parts.password:
                refs.append(url)
        except ValueError:
            continue
    cwes = {d["value"] for w in record.get("weaknesses",[]) for d in w.get("description",[])
            if re.fullmatch(r"CWE-\d+", str(d.get("value","")))}
    if not record.get("lastModified") or not CVE_ID.fullmatch(record.get("id","")):
        return
    values = dict(cve_id=record["id"],source="NVD",as_of=record["lastModified"],
                  details={"cwe":sorted(cwes),"vendor_advisories":sorted(set(refs))})
    stmt = insert(CVEContext).values(**values)
    db.execute(stmt.on_conflict_do_update(index_elements=["cve_id","source"],
               set_={"details":stmt.excluded.details,"as_of":stmt.excluded.as_of},
               where=CVEContext.as_of<=stmt.excluded.as_of))


def contextualize(row):
    try:
        age=(datetime.now(timezone.utc).date()-date.fromisoformat(row.as_of[:10])).days
    except ValueError:
        age=None
    return {"source":row.source,"as_of":row.as_of,"age_days":age,
            "stale":(age is None or age<0 or age>7) if row.source!="NVD" else None,"details":row.details}
