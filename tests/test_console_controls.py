"""Session middleware and real routes; no database, scanner, or CVE downloads."""
import re
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient


def token(page):
    assert page.status_code == 200
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


@pytest.fixture
def ctx(monkeypatch):
    import dotenv
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *args, **kwargs: False)
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test@127.0.0.1:1/test")
    monkeypatch.setenv("COOKIE_SECURE", "0")
    import main
    import auth
    db = Mock()
    monkeypatch.setattr(main, "SessionLocal", db)
    user = SimpleNamespace(id=7, username="operator", full_name="Operator", role="admin",
                           is_active=True, password_hash="fixture", is_2fa_exempt=True)
    monkeypatch.setattr(main.store, "get_user_by_username", lambda *args: user)
    monkeypatch.setattr(auth, "verify_password", lambda *args: True)
    monkeypatch.setattr(auth, "current_user", lambda r: user if r.session.get("uid")==7 else None)
    monkeypatch.setattr(auth, "pending_user", lambda r: user if r.session.get("pending_uid")==7 else None)
    return TestClient(main.app, follow_redirects=False), main, user, db


def login(client, **extra):
    csrf = token(client.get("/login"))
    response = client.post("/login", data={"username":"operator", "password":"fixture", "csrf_token":csrf, **extra})
    assert response.status_code == 303
    return csrf, response.headers["location"]


def test_login_logout_and_session_binding(ctx):
    client, _, _, db = ctx
    assert client.post("/login", data={"username":"a","password":"b"}).status_code == 403
    db.assert_not_called()


def test_missing_startup_secrets_cannot_provision_accounts(ctx,monkeypatch,capsys):
    import auth
    db=Mock()
    monkeypatch.setattr(auth,"SessionLocal",lambda:db)
    db.query.return_value.count.return_value=0
    monkeypatch.delenv("ADMIN_PASSWORD",raising=False)
    monkeypatch.delenv("BREAKGLASS_PASSWORD",raising=False)
    with pytest.raises(RuntimeError,match="ADMIN_PASSWORD"):
        auth.seed_admin()
    auth.seed_breakglass()
    db.add.assert_not_called()
    db.commit.assert_not_called()
    assert not capsys.readouterr().out


def test_emergency_secret_never_logged_or_applied_to_an_ordinary_account(ctx,monkeypatch,capsys):
    import auth
    db=Mock()
    monkeypatch.setattr(auth,"SessionLocal",lambda:db)
    monkeypatch.setattr(auth,"hash_password",lambda _: "fixture-hash")
    monkeypatch.setenv("BREAKGLASS_PASSWORD","fixture-only-secret")
    lookup=db.query.return_value.filter.return_value.first
    lookup.return_value=None
    auth.seed_breakglass()
    assert db.add.call_args.args[0].password_hash=="fixture-hash"
    assert "fixture-only-secret" not in capsys.readouterr().out
    db.reset_mock()
    lookup.return_value=SimpleNamespace(role="customer",is_2fa_exempt=False)
    with pytest.raises(RuntimeError,match="conflicts"):
        auth.seed_breakglass()
    db.commit.assert_not_called()
    lookup.return_value=SimpleNamespace(role="admin",is_2fa_exempt=True,is_active=False)
    auth.seed_breakglass()
    assert not lookup.return_value.is_active
    db.commit.assert_not_called()


@pytest.mark.parametrize(("method","path","body"),[
    ("POST","/api/discovery",None),
    ("POST","/api/network-scans",{"networks":["192.0.2.0/30"],"approval":""}),
    ("POST","/api/network-login-checks",{"scan_id":"fixture","approval":""}),
    ("POST","/api/devices/identify",{"target":"192.0.2.1"}),
    ("DELETE","/api/scans/fixture",None),
])
def test_existing_admin_api_deny_matrix(ctx,method,path,body):
    client, _, user, db=ctx
    assert client.request(method,path,json=body).status_code==401
    login(client)
    valid=token(client.get("/risks"))
    db.reset_mock()
    user.role="analyst"
    assert client.request(method,path,json=body,headers={"X-CSRF-Token":valid}).status_code==403
    user.role="admin"
    assert client.request(method,path,json=body).status_code==403
    db.assert_not_called()


def test_logout_rotation_and_redirect(ctx):
    client, _, _, _ = ctx
    old, location = login(client, next="//outside.invalid")
    assert location == "/"
    assert client.get("/logout").status_code == 405
    assert client.post("/logout", data={"csrf_token":old}).status_code == 403
    current = token(client.get("/risks"))
    other = TestClient(client.app)
    assert other.post("/logout", data={"csrf_token":current}).status_code == 403
    assert client.post("/logout", data={"csrf_token":current}).status_code == 303
    assert client.get("/api/scans").status_code == 401


@pytest.mark.parametrize(("path","fields"), [
    ("/clients", {"name":"test"}), ("/tokens", {"client_id":1,"scan_limit":1}),
    ("/tokens/9/revoke", {}), ("/admin/users", {"username":"test","password":"fixture"}),
    ("/admin/users/9/reset-2fa", {}),
])
def test_admin_writes_fail_before_storage(ctx,path,fields):
    client, _, user, db = ctx
    assert client.post(path,data=fields).headers["location"] == "/login"
    login(client)
    db.reset_mock()
    assert client.post(path,data=fields).status_code == 403
    valid=token(client.get("/risks"))
    user.role="analyst"
    assert client.post(path,data={**fields,"csrf_token":valid}).headers["location"] == "/"
    db.assert_not_called()


@pytest.mark.parametrize(("path","body"),[
    ("/scan",{"target":"fixture","vendor":"fixture","product":"fixture"}),
    ("/scan-web",{"url":"https://example.invalid"}),
    ("/api/risk-status",{"scan_type":"pc","scan_id":"fixture","cve_id":"fixture","accepted":True}),
])
def test_operator_writes_require_session_and_token(ctx,path,body):
    client, _, _, db=ctx
    assert client.post(path,json=body).status_code==401
    login(client)
    db.reset_mock()
    assert client.post(path,json=body).status_code==403
    db.assert_not_called()


def test_admin_sync_and_revoke(ctx,monkeypatch):
    client, main, user, db=ctx
    job, revoke=Mock(), Mock()
    monkeypatch.setattr(main,"sync_cves",job)
    monkeypatch.setattr(main.store,"revoke_token",revoke)
    assert client.post("/sync").status_code==401
    login(client)
    valid=token(client.get("/risks"))
    user.role="analyst"
    assert client.post("/sync",headers={"X-CSRF-Token":valid}).status_code==403
    user.role="admin"
    assert client.post("/sync").status_code==403
    job.assert_not_called()
    assert client.post("/sync",headers={"X-CSRF-Token":valid}).status_code==200
    job.assert_called_once()
    assert client.post("/tokens/9/revoke",data={"csrf_token":valid}).status_code==303
    revoke.assert_called_once_with(db.return_value,9)


@pytest.mark.parametrize("step",["verify","enroll"])
def test_pending_2fa_forms(ctx,step):
    client, _, user, db=ctx
    user.is_2fa_exempt=False
    user.totp_secret="fixture" if step=="verify" else None
    old, location=login(client)
    assert location=="/2fa/"+step
    assert token(client.get(location))!=old
    db.reset_mock()
    assert client.post(location,data={"code":"000000","csrf_token":old}).status_code==403
    assert client.get("/api/scans").status_code==401
    db.assert_not_called()
