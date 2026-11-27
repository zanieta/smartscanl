"""Index historical reports in bounded deterministic batches. Safe to repeat."""
import json
from db.inventory import project
from db.models import Scan


def backfill(db):
    indexed=skipped=0
    after=""
    while True:
        rows=db.query(Scan).filter(Scan.scan_id>after).order_by(Scan.scan_id).limit(200).all()
        if not rows:
            return indexed,skipped
        for row in rows:
            after=row.scan_id
            try:
                payload=json.loads(row.payload)
            except (ValueError,TypeError):
                skipped+=1
                continue
            if project(db,row,payload):
                indexed+=1
            else:
                skipped+=1
        db.commit()


if __name__=="__main__":
    from db.session import SessionLocal
    with SessionLocal() as db:
        indexed,skipped=backfill(db)
    print(f"Indexable: {indexed}; skipped: {skipped}")
