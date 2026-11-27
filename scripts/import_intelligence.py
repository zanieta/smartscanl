"""Import a complete official CISA KEV JSON or FIRST EPSS daily CSV (.gz accepted).

Downloads are out of band. No asset identifiers or customer data leave this host.
Validate before replacing a source snapshot; the caller commits only on success.
"""
import argparse
import csv
from datetime import date
import gzip
import json
from itertools import chain
import math
import re
from pathlib import Path
from sqlalchemy import text
from db.models import CVEContext
from sync.intelligence import CVE_ID


def replace(db, source, stream):
    if source=="KEV":
        doc=json.load(stream)
        entries=doc["vulnerabilities"]
        if not entries or len(entries)!=doc["count"]:
            raise ValueError("Empty or incomplete KEV catalog")
        stamp=date.fromisoformat(doc["dateReleased"][:10]).isoformat()
        records=((r["cveID"],{"listed":True,"added":date.fromisoformat(r["dateAdded"]).isoformat()}) for r in entries)
    elif source=="EPSS":
        first=next(stream,"")
        header_day=re.search(r"(?:^|[,#])score_date:(\d{4}-\d{2}-\d{2})",first) if first.startswith("#") else None
        reader=csv.DictReader(stream if first.startswith("#") else chain([first],stream))
        def scores():
            nonlocal stamp
            for row in reader:
                day=date.fromisoformat(row.get("date") or (header_day.group(1) if header_day else "")).isoformat()
                if stamp and stamp!=day:
                    raise ValueError("Mixed EPSS snapshot dates")
                stamp=day
                value=float(row["epss"])
                if not math.isfinite(value) or not 0<=value<=1:
                    raise ValueError("Invalid EPSS probability")
                yield row["cve"],{"probability":value}
        stamp=None
        records=scores()
    else:
        raise ValueError("Unknown source")
    # Serialize imports of the same catalog. A malformed file rolls back the transaction.
    db.execute(text("select pg_advisory_xact_lock(:key)"),{"key":309301 if source=="KEV" else 309302})
    previous=db.query(CVEContext.as_of).filter_by(source=source).limit(1).scalar()
    db.query(CVEContext).filter_by(source=source).delete(synchronize_session=False)
    batch=[]
    count=0
    for cve,details in records:
        if not CVE_ID.fullmatch(cve) or (previous and stamp<previous):
            raise ValueError("Invalid identifier or older snapshot")
        batch.append(dict(cve_id=cve,source=source,as_of=stamp,details=details))
        count+=1
        if len(batch)>=1000:
            db.execute(CVEContext.__table__.insert(),batch)
            batch=[]
    if not count:
        raise ValueError("Empty snapshot")
    if batch:
        db.execute(CVEContext.__table__.insert(),batch)
    return count


if __name__=="__main__":
    from db.session import SessionLocal
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",choices=["KEV","EPSS"])
    parser.add_argument("file",type=Path)
    args=parser.parse_args()
    opener=gzip.open if args.file.suffix==".gz" else open
    with opener(args.file,"rt",encoding="utf-8-sig",newline="") as stream, SessionLocal.begin() as db:
        count=replace(db,args.source,stream)
    print(f"Imported {count} {args.source} records")
