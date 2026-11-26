"""Run only on the named test DB. An outer transaction rolls back schema and data."""
import json
import os
import re
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def tenant_env(monkeypatch):
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set TEST_DATABASE_URL to the throwaway vulnsense_test PostgreSQL database")
    assert make_url(url).get_backend_name() == "postgresql" and make_url(url).database == "vulnsense_test"
    import dotenv
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *args, **kwargs: False)
    monkeypatch.setenv("DATABASE_URL", url)
    import auth
    import main
    from db.models import Base, Client, ClientMembership, Scan, ScanToken, User

    engine = create_engine(url)
    with engine.connect() as conn:
        outer = conn.begin()
        schema = "m2_" + uuid.uuid4().hex
        try:
            conn.execute(text("CREATE SCHEMA " + schema))
            conn.execute(text("SET LOCAL search_path TO " + schema))
            legacy = [t for t in Base.metadata.sorted_tables if t.name not in {"client_memberships","membership_events"}]
            Base.metadata.create_all(conn,tables=legacy)
            conn.execute(text("INSERT INTO scans (scan_id,scan_type,payload) VALUES ('preexisting','pc','{}')"))
            Base.metadata.create_all(conn)
            Base.metadata.create_all(conn)
            assert conn.scalar(text("SELECT count(*) FROM scans WHERE scan_id='preexisting' AND client_id IS NULL"))==1
            assert conn.scalar(text("SELECT count(*) FROM client_memberships"))==0
            conn.execute(text("DELETE FROM scans WHERE scan_id='preexisting'"))
            local = sessionmaker(bind=conn, join_transaction_mode="create_savepoint")
            monkeypatch.setattr(main, "SessionLocal", local)
            with local() as db:
                db.add_all([Client(id=i,name=f"Org-{i}") for i in (1,2)])
                db.add_all([User(id=i,username=f"u{i}",role=r,password_hash="fixture")
                            for i,r in enumerate(["admin","customer","customer","analyst","analyst"],1)])
                db.flush()
                db.add_all([ClientMembership(user_id=u,client_id=c) for u,c in [(2,1),(3,2),(4,1),(4,2)]])
                for c in [1,2,None]:
                    for kind in ["pc","web"]:
                        sid = f"{kind}-{c}"
                        payload = dict(scan_id=sid,host=sid,url=sid,cves_found=1,critical_count=0,high_count=1,
                                       open_ports=[],findings=[dict(cve_id="TEST",severity="High",description="Fixture")])
                        db.add(Scan(scan_id=sid,scan_type=kind,client_id=c,payload=json.dumps(payload)))
                for c in (1,2):
                    db.add(ScanToken(token=f"fixture-{c}",client_id=c))
                db.commit()
            user = SimpleNamespace(id=2,role="customer",username="sample",full_name="Sample")
            monkeypatch.setattr(auth, "current_user", lambda request: user)
            client = TestClient(main.app,follow_redirects=False)
            csrf = re.search(r'name="csrf-token" content="([^"]+)"',client.get("/risks").text).group(1)
            client.headers.update({"X-CSRF-Token":csrf})
            yield client,user,local,main
        finally:
            outer.rollback()
    engine.dispose()


@pytest.mark.parametrize(("kind","path","listing"),[("pc","report","scans"),("web","web-report","web-scans")])
def test_scoped_reads_and_exports(tenant_env,kind,path,listing):
    client,user,_,_=tenant_env
    for uid,role,visible in [(2,"customer",[1]),(3,"customer",[2]),(4,"analyst",[1,2]),
                             (5,"analyst",[]),(1,"admin",[1,2,None])]:
        user.id,user.role=uid,role
        assert {r["scan_id"] for r in client.get("/api/"+listing).json()["scans"]}=={f"{kind}-{c}" for c in visible}
        assert {r["client_id"] for r in client.get("/api/scans-by-client").json()["clients"]}==set(visible)-{None}
        for c in (1,2,None):
            for ext in ("","/html","/pdf"):
                response=client.get(f"/{path}/{kind}-{c}{ext}")
                assert response.status_code==(200 if c in visible else 404),response.text[:120]
                assert "no-store" in response.headers["cache-control"]
                if ext=="/pdf" and c in visible:
                    assert response.content.startswith(b"%PDF")


def test_admin_grants_and_writes(tenant_env):
    from db.models import MembershipEvent, Scan
    client,user,local,main=tenant_env
    form={"client_id":2,"user_id":2,"action":"grant"}
    assert client.post("/admin/memberships",data=form).headers["location"]=="/"
    assert client.get("/pc").status_code==403
    assert client.get("/web").status_code==403
    decision=dict(scan_type="pc",scan_id="pc-1",cve_id="TEST",accepted=True)
    assert client.post("/api/risk-status",json=decision).status_code==403
    user.role,user.id="admin",1
    assert client.post("/admin/memberships",data=form).status_code==409
    assert client.get("/admin/users").status_code==200
    assignment={"user_id":4,"client_id":2,"action":"revoke"}
    for _ in range(2):
        assert client.post("/admin/memberships",data=assignment).status_code==303
    user.role,user.id="analyst",4
    assert client.get("/report/pc-2").status_code==404
    assert client.post("/api/risk-status",json={**decision,"scan_id":"pc-2"}).status_code==404
    assert client.post("/api/risk-status",json=decision).status_code==200
    assert client.delete("/api/scans/pc-2").status_code==403
    for path in ["/pc","/web"]:
        body=client.get(path).text
        assert "fixture-1" in body and "fixture-2" not in body
    with pytest.raises(main.HTTPException) as denied:
        main._validate_token("fixture-2",user)
    assert denied.value.status_code==403
    with local() as db:
        assert db.query(MembershipEvent).count()==1
        assert "accepted" not in db.get(Scan,"pc-2").payload
    user.role,user.id="admin",1
    assignment["action"]="grant"
    assert client.post("/admin/memberships",data=assignment).status_code==303
    user.role,user.id="analyst",4
    assert client.get("/report/pc-2").status_code==200
