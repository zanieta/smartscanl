"""Exercise real customer login against the temporary local database of the restore rehearsal."""
import os
from pathlib import Path
import re
import secrets
import sys
from uuid import UUID

from sqlalchemy.engine import make_url


def main(scan_id):
    url = make_url(os.environ["DATABASE_URL"])
    socket = Path(url.query.get("host", "")).resolve()
    if (url.get_backend_name() != "postgresql" or url.host or url.database != "ubuntu_readback"
            or socket.parent != Path("/tmp") or not socket.name.startswith("security360-rehearsal.")
            or socket.stat().st_uid != os.getuid() or socket.stat().st_mode & 0o077
            or os.getuid() == 0 or os.environ.get("PYTHON_DOTENV_DISABLED") != "1"):
        raise SystemExit("Refusing to run outside an owned disposable Ubuntu rehearsal.")
    from fastapi.testclient import TestClient
    import pyotp
    import auth
    import main as console
    from db.models import ClientMembership, User
    from db.session import SessionLocal

    secret, password = pyotp.random_base32(), secrets.token_urlsafe(32)
    with SessionLocal.begin() as db:
        user = User(username="rehearsal-customer", role="customer", totp_secret=secret,
                    password_hash=auth.hash_password(password), is_active=True)
        db.add(user)
        db.flush()
        db.add(ClientMembership(user_id=user.id, client_id=1))
    client = TestClient(console.app, base_url="https://testserver", follow_redirects=False)
    def csrf(path):
        response = client.get(path)
        assert response.status_code == 200
        return re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)
    route = "/api/ubuntu-evidence/" + str(UUID(scan_id))
    assert client.get(route).status_code == 401
    login = client.post("/login", data={"username":"rehearsal-customer", "password":password,
                                       "csrf_token":csrf("/login")})
    assert login.headers["location"] == "/2fa/verify"
    assert client.get(route).status_code == 401
    token = csrf("/2fa/verify")
    assert client.post("/2fa/verify", data={"code":pyotp.TOTP(secret).now(),"csrf_token":token}).status_code == 303
    raw = client.get(route)
    assert raw.status_code == 200 and raw.json()["scan_id"] == scan_id and len(raw.json()["packages"]) == 5
    counts = client.get(route+"/review").json()["counts"]
    assert sum(counts.values()) == 2
    for fmt, signature in (("xlsx", b"PK"), ("pdf", b"%PDF"), ("csv", b"scan_id,"), ("json", b"{")):
        response = client.get(route+"/export/"+fmt)
        assert response.status_code == 200 and response.content.startswith(signature)
    assert len(client.get(route+"/export/json").json()["findings"]) == counts["open"]
    print("PASS: Ubuntu collection, PostgreSQL restore, customer sign-in plus OTP, scoped review and four downloads")


if __name__ == "__main__":
    main(sys.argv[1])
