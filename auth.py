"""Authentication for the SmartScan console.

Two tiers of auth (see the deployment model):
  * People  -> a signed session cookie set at login (this module).
  * Remote scan requests -> a ScanToken carried with the request (see db.tokens).

Passwords are hashed with PBKDF2-HMAC-SHA256 from the standard library, so there
is no third-party crypto dependency to install.

Sign-in is two-factor. A password check alone only reaches the *pending* state
(``pending_uid``); a valid TOTP code promotes it to the authenticated state
(``uid``). Every guard below reads ``uid``, so a half-authenticated session is
inert against the whole app without any guard needing to know 2FA exists.

The one exception is the break-glass account (``is_2fa_exempt``), which signs in
on a password alone. Its credentials come from the environment, never source.
"""
import os
import time
import hmac
import base64
import hashlib
import secrets

import pyotp
import segno

from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse

from db.session import SessionLocal
from db.models import User

PBKDF2_ALGO = "pbkdf2_sha256"
PBKDF2_ITERS = 240_000

# Single source of truth: the server check and the browser's minlength hint both
# read this, so the two can't drift apart.
MIN_PASSWORD_LEN = 8

TOTP_ISSUER = "DeWebnet"       # bold line in the authenticator app
TOTP_ACCOUNT = "SmartScan"     # product, shown with the username beneath the issuer
TOTP_STEP = 30           # seconds per code, RFC 6238 default
TOTP_DRIFT_STEPS = 1     # accept +/- one step, to tolerate phone clock skew
MAX_TOTP_FAILURES = 5    # consecutive bad codes before the pending session is dropped


# ===================== password hashing =====================

def hash_password(password: str) -> str:
    """Return a self-describing hash: 'pbkdf2_sha256$iters$salt_b64$hash_b64'."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return "$".join([
        PBKDF2_ALGO,
        str(PBKDF2_ITERS),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    ])


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored PBKDF2 hash."""
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != PBKDF2_ALGO:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ===================== session helpers =====================

def login_session(request: Request, user: User) -> None:
    """Fully authenticate. Clears any half-finished 2FA state."""
    clear_pending(request)
    request.session["uid"] = user.id


def logout_session(request: Request) -> None:
    request.session.pop("uid", None)
    clear_pending(request)


# ===================== pending (password ok, 2FA outstanding) =====================

def begin_pending(request: Request, user: User) -> None:
    """Password verified; hold the user here until a TOTP code lands."""
    request.session.pop("uid", None)
    request.session["pending_uid"] = user.id


def pending_user(request: Request):
    """The half-authenticated User, or None. Never satisfies a guard."""
    uid = request.session.get("pending_uid")
    if not uid:
        return None
    db = SessionLocal()
    try:
        return db.query(User).filter(User.id == uid, User.is_active == True).first()  # noqa: E712
    finally:
        db.close()


def clear_pending(request: Request) -> None:
    request.session.pop("pending_uid", None)
    request.session.pop("totp_candidate", None)


def require_pending(request: Request) -> User:
    """Guard for the /2fa/* pages: you got past the password, or you go back."""
    user = pending_user(request)
    if not user:
        raise RedirectException("/login")
    return user


# ===================== TOTP =====================

def new_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(username: str, secret: str) -> str:
    """otpauth:// URI an authenticator app consumes.

    Renders in Google Authenticator as "DeWebnet" over "SmartScan (username)".
    The username is kept so two accounts enrolled on one phone stay distinguishable.
    """
    return pyotp.TOTP(secret).provisioning_uri(
        name=f"{TOTP_ACCOUNT} ({username})", issuer_name=TOTP_ISSUER)


def totp_qr_svg(uri: str) -> str:
    """Inline SVG for the enrollment QR. segno is pure-Python: no Pillow, no temp file.

    omitsize=True swaps segno's fixed width/height for a viewBox. Without it the
    SVG has no viewBox, so any CSS that sizes the element *clips* the QR instead of
    scaling it — the cropped result will not decode in an authenticator app.
    """
    return segno.make(uri, error="m").svg_inline(scale=5, dark="#11178C", omitsize=True)


def matched_counter(secret: str, code: str):
    """Return the 30s time-step the code is valid for, or None.

    We need the *step*, not just a yes/no, so the caller can reject a code whose
    step was already spent (replay inside the same 30s window).
    """
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now = int(time.time())
    for offset in range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1):
        at = now + offset * TOTP_STEP
        if hmac.compare_digest(totp.at(at), code):
            return at // TOTP_STEP
    return None


def verify_totp(db, user: User, code: str) -> bool:
    """Check a code against an enrolled user, enforcing replay + failure limits.

    Commits the counter/failure bookkeeping, so ``user`` must be attached to ``db``.
    """
    if not user.totp_secret:
        return False

    step = matched_counter(user.totp_secret, code)
    replayed = step is not None and user.totp_last_counter is not None \
        and step <= user.totp_last_counter

    if step is None or replayed:
        user.totp_failures = (user.totp_failures or 0) + 1
        db.commit()
        return False

    user.totp_last_counter = step
    user.totp_failures = 0
    db.commit()
    return True


def totp_locked_out(user: User) -> bool:
    return (user.totp_failures or 0) >= MAX_TOTP_FAILURES


def current_user(request: Request):
    """The logged-in User (detached), or None. Scalar columns stay readable."""
    uid = request.session.get("uid")
    if not uid:
        return None
    db = SessionLocal()
    try:
        return db.query(User).filter(User.id == uid, User.is_active == True).first()  # noqa: E712
    finally:
        db.close()


# ===================== guards =====================

class RedirectException(Exception):
    """Raised by page guards to send a browser to /login (handled by a FastAPI
    exception handler in main.py)."""
    def __init__(self, location: str):
        self.location = location


def require_user(request: Request) -> User:
    """Page guard: returns the user or redirects to /login."""
    user = current_user(request)
    if not user:
        raise RedirectException("/login")
    return user


def require_admin_page(request: Request) -> User:
    """Page guard: returns an admin user, else redirect to /login or home."""
    user = current_user(request)
    if not user:
        raise RedirectException("/login")
    if user.role != "admin":
        raise RedirectException("/")
    return user


def require_user_api(request: Request) -> User:
    """API guard (JSON): 401 when not logged in."""
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated. Please sign in.")
    return user


def require_admin_api(request: Request) -> User:
    user = require_user_api(request)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return user


# ===================== seeding & secrets =====================

def get_session_secret() -> str:
    """Stable secret for cookie signing. Set SESSION_SECRET in .env in prod;
    a random fallback works but invalidates sessions on restart."""
    secret = os.getenv("SESSION_SECRET")
    if not secret:
        secret = secrets.token_hex(32)
        print("[auth] SESSION_SECRET not set — using a random key (sessions reset on restart).")
    return secret


def seed_admin() -> None:
    """Create the initial admin if there are no users yet."""
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        username = os.getenv("ADMIN_USERNAME", "admin")
        password = os.getenv("ADMIN_PASSWORD", "admin")
        admin = User(
            username=username,
            full_name="Administrator",
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print(f"[auth] Seeded initial admin '{username}'. "
              f"{'CHANGE THE DEFAULT PASSWORD in production.' if password == 'admin' else ''}")
    finally:
        db.close()


BREAKGLASS_USERNAME = os.getenv("BREAKGLASS_USERNAME", "dewebnetadmin")


def seed_breakglass() -> None:
    """Ensure the 2FA-exempt break-glass admin exists.

    Password comes from BREAKGLASS_PASSWORD (.env, gitignored). If unset we mint a
    random one and print it once — a weak default nobody rotates is worse than a
    strong one you must go read out of the log. `.env` stays the source of truth:
    change the value there and the password is updated on the next restart.

    Call this AFTER seed_admin(), which only seeds when the users table is empty.
    """
    password = os.getenv("BREAKGLASS_PASSWORD")
    generated = False
    if not password:
        password = secrets.token_urlsafe(18)
        generated = True

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == BREAKGLASS_USERNAME).first()
        if user is None:
            db.add(User(
                username=BREAKGLASS_USERNAME,
                full_name="DEWEBNET Break-glass Administrator",
                password_hash=hash_password(password),
                role="admin",
                is_active=True,
                is_2fa_exempt=True,
            ))
            db.commit()
            # flush=True: under gunicorn+systemd stdout is block-buffered, and a
            # generated password printed into a buffer is a password lost forever.
            print(f"[auth] Seeded break-glass admin '{BREAKGLASS_USERNAME}' (2FA-exempt).",
                  flush=True)
            if generated:
                print(f"[auth] BREAKGLASS_PASSWORD was unset. Generated: {password}\n"
                      f"[auth] Save it now — it will not be shown again.", flush=True)
            return

        # Account exists. Keep .env authoritative for the password, and make sure a
        # DB edited by hand can't quietly strip the exemption.
        changed = []
        if not generated and not verify_password(password, user.password_hash):
            user.password_hash = hash_password(password)
            changed.append("password")
        if not user.is_2fa_exempt:
            user.is_2fa_exempt = True
            changed.append("2FA exemption")
        if not user.is_active:
            user.is_active = True
            changed.append("active flag")
        if changed:
            db.commit()
            print(f"[auth] Break-glass admin '{BREAKGLASS_USERNAME}': "
                  f"restored {', '.join(changed)} from environment.", flush=True)
    finally:
        db.close()
