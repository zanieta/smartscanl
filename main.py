import uuid
import os
import logging
import secrets
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Depends, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from scanner.nmap_scanner import run_scan
from scanner.parser import parse_scan_result, detected_product_version
from scanner.web_scanner import run_web_scan
from scanner.web_checks import parse_web_result, run_passive_checks, banner_to_targets, banner_version
from agent.llm_agent import analyze_vulnerabilities, analyze_web_vulnerabilities
from reports.formatter import format_report_data, format_web_report_data
from reports.pdf_report import build_pdf

from db.session import SessionLocal, init_db
from db.queries import find_cves, os_to_target
from db.models import SyncLog, User, DiscoveryRun
from db import store
from sync.nvd_sync import sync_cves

import auth
from auth import (
    current_user, require_user, require_admin_page,
    require_user_api, require_admin_api, require_pending, RedirectException,
    MIN_PASSWORD_LEN,
)

# override=True so the project's .env wins over any stale OS-level env vars.
load_dotenv(override=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Order matters: seed_admin() only fires when the users table is empty, so it
    # must run before seed_breakglass() adds a row.
    auth.seed_admin()
    auth.seed_breakglass()

    # Rehydrate the in-memory report caches from persisted scans so history and
    # report/PDF rendering survive restarts.
    db = SessionLocal()
    try:
        reports_db.update(store.load_payloads(db, "pc"))
        web_reports_db.update(store.load_payloads(db, "web"))
    finally:
        db.close()

    yield


app = FastAPI(title="SmartScan AI Vulnerability Scanner", lifespan=lifespan)
# https_only adds the cookie `Secure` flag. Env-gated: off for Phase 0 plain-HTTP
# (WSL2) so login works; set COOKIE_SECURE=1 in the server .env behind TLS (Phase 1).
app.add_middleware(
    SessionMiddleware,
    secret_key=auth.get_session_secret(),
    same_site="lax",
    https_only=os.getenv("COOKIE_SECURE") == "1",
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.exception_handler(RedirectException)
async def _redirect_handler(request: Request, exc: RedirectException):
    return RedirectResponse(exc.location, status_code=303)


# In-memory caches, kept in sync with the persisted `scans` table.
reports_db = {}
web_reports_db = {}


class ScanRequest(BaseModel):
    target: str
    vendor: str
    product: str
    token: str = ""
    version: str | None = None


class WebScanRequest(BaseModel):
    url: str
    token: str = ""


class RiskStatusRequest(BaseModel):
    scan_type: str   # "pc" or "web"
    scan_id: str
    cve_id: str
    accepted: bool


def _page(request: Request, name: str, active: str, user, **extra):
    request.session.setdefault("csrf_token", secrets.token_urlsafe(32))
    ctx = {"active": active, "user": user, "csrf_token": request.session["csrf_token"]}
    ctx.update(extra)
    return templates.TemplateResponse(request=request, name=name, context=ctx)


def _check_csrf(request: Request) -> None:
    expected = request.session.get("csrf_token", "")
    supplied = request.headers.get("x-csrf-token", "")
    if not expected or not secrets.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Reload the page and try again.")


def _recount(report: dict) -> None:
    """Recompute critical/high counts, excluding findings marked accepted."""
    crit = high = 0
    for f in report.get("findings", []):
        if str(f.get("status", "open")).lower() == "accepted":
            continue
        sev = str(f.get("severity", "")).lower()
        if sev == "critical":
            crit += 1
        elif sev == "high":
            high += 1
    report["critical_count"] = crit
    report["high_count"] = high


def _validate_token(token_value: str):
    """Fail fast before running a scan. Returns (client_id, client_name)."""
    db = SessionLocal()
    try:
        tok = store.get_token_by_value(db, token_value)
        if tok is None:
            raise HTTPException(status_code=403, detail="Invalid scan token.")
        if not tok.is_spendable:
            raise HTTPException(
                status_code=403,
                detail=f"Token exhausted ({tok.uses}/{tok.scan_limit} scans used). "
                       f"Ask an admin to generate a new one.",
            )
        return tok.client_id, (tok.client.name if tok.client else None)
    finally:
        db.close()


def _finalize_scan(report: dict, scan_type: str, token_value: str, user: User) -> None:
    """Stamp client/operator metadata, spend the token, and persist the scan."""
    report["created_at"] = _now()
    report["operator"] = user.username if user else None
    target = report.get("host") or report.get("url")
    db = SessionLocal()
    try:
        tok = store.get_token_by_value(db, token_value)
        if tok is not None:
            report["client_id"] = tok.client_id
            report["client_name"] = tok.client.name if tok.client else None
            store.consume_token(db, tok, user.id if user else None,
                                target, report["scan_id"], scan_type)
        store.persist_scan(db, report, scan_type,
                           report.get("client_id"), user.id if user else None, target)
    finally:
        db.close()


# ===================== auth pages =====================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "", next: str = "/"):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request=request, name="login.html",
        context={"error": error, "next": next},
    )


@app.post("/login")
async def login_submit(request: Request, username: str = Form(...),
                       password: str = Form(...), next: str = Form("/")):
    db = SessionLocal()
    try:
        user = store.get_user_by_username(db, username.strip())
        ok = user and user.is_active and auth.verify_password(password, user.password_hash)
        if not ok:
            return templates.TemplateResponse(
                request=request, name="login.html",
                context={"error": "Incorrect username or password.", "next": next},
                status_code=401,
            )

        # Break-glass: password is the only factor. Loudly audited, because an
        # unwatched exempt account is just a backdoor.
        if user.is_2fa_exempt:
            # flush=True: gunicorn block-buffers stdout, and an audit line that
            # never reaches journalctl is not an audit line.
            print(f"[audit] BREAK-GLASS LOGIN: '{user.username}' from "
                  f"{request.client.host if request.client else 'unknown'} at {_now()}",
                  flush=True)
            auth.login_session(request, user)
            return RedirectResponse(next or "/", status_code=303)

        # Everyone else: password only reaches the pending state.
        auth.begin_pending(request, user)
        request.session["pending_next"] = next or "/"
        destination = "/2fa/verify" if user.totp_secret else "/2fa/enroll"
    finally:
        db.close()
    return RedirectResponse(destination, status_code=303)


@app.get("/logout")
async def logout(request: Request):
    auth.logout_session(request)
    return RedirectResponse("/login", status_code=303)


# ===================== two-factor auth =====================

def _finish_2fa(request: Request, user: User) -> RedirectResponse:
    """Promote pending -> authenticated and go where the user was headed."""
    destination = request.session.get("pending_next") or "/"
    request.session.pop("pending_next", None)
    auth.login_session(request, user)      # clears pending_uid + totp_candidate
    return RedirectResponse(destination, status_code=303)


@app.get("/2fa/enroll", response_class=HTMLResponse)
async def totp_enroll_page(request: Request, error: str = ""):
    user = require_pending(request)
    if user.totp_secret:
        return RedirectResponse("/2fa/verify", status_code=303)

    # Hold the candidate secret in the session, NOT in `users`. Committing it on
    # page render would strand anyone who loads this page and closes the tab:
    # 2FA is mandatory, so they'd be locked out by a secret they never scanned.
    secret = request.session.get("totp_candidate")
    if not secret:
        secret = auth.new_totp_secret()
        request.session["totp_candidate"] = secret

    uri = auth.provisioning_uri(user.username, secret)
    return templates.TemplateResponse(
        request=request, name="2fa_enroll.html",
        context={"qr_svg": auth.totp_qr_svg(uri), "secret": secret,
                 "username": user.username, "error": error},
    )


@app.post("/2fa/enroll")
async def totp_enroll_submit(request: Request, code: str = Form(...)):
    user = require_pending(request)
    secret = request.session.get("totp_candidate")
    if not secret:
        return RedirectResponse("/2fa/enroll", status_code=303)

    step = auth.matched_counter(secret, code)
    if step is None:
        return RedirectResponse(
            "/2fa/enroll?error=That+code+is+not+valid.+Check+your+authenticator+and+try+again.",
            status_code=303)

    # Proven: the authenticator holds the secret. Only now does it persist.
    db = SessionLocal()
    try:
        row = db.query(User).filter(User.id == user.id).first()
        row.totp_secret = secret
        row.totp_last_counter = step
        row.totp_failures = 0
        db.commit()
        print(f"[audit] 2FA enrolled for '{row.username}' at {_now()}", flush=True)
        return _finish_2fa(request, row)
    finally:
        db.close()


@app.get("/2fa/verify", response_class=HTMLResponse)
async def totp_verify_page(request: Request, error: str = ""):
    user = require_pending(request)
    if not user.totp_secret:
        return RedirectResponse("/2fa/enroll", status_code=303)
    return templates.TemplateResponse(
        request=request, name="2fa_verify.html",
        context={"username": user.username, "error": error},
    )


@app.post("/2fa/verify")
async def totp_verify_submit(request: Request, code: str = Form(...)):
    user = require_pending(request)
    db = SessionLocal()
    try:
        row = db.query(User).filter(User.id == user.id).first()
        if auth.verify_totp(db, row, code):
            return _finish_2fa(request, row)

        # Too many misses: drop the pending session. Guessing further now costs
        # the attacker a fresh password authentication.
        if auth.totp_locked_out(row):
            row.totp_failures = 0
            db.commit()
            auth.clear_pending(request)
            print(f"[audit] 2FA lockout for '{row.username}' at {_now()} — pending session dropped",
                  flush=True)
            return RedirectResponse(
                "/login?error=Too+many+incorrect+codes.+Please+sign+in+again.",
                status_code=303)
    finally:
        db.close()

    return RedirectResponse("/2fa/verify?error=Incorrect+code.+Try+the+current+one.",
                            status_code=303)


# ===================== dashboard / scanners (login required) =====================

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    user = require_user(request)
    return _page(request, "overview.html", "dashboard", user)


@app.get("/pc", response_class=HTMLResponse)
async def get_pc_scanner(request: Request):
    user = require_user(request)
    db = SessionLocal()
    try:
        tokens = [t for t in store.list_tokens(db) if t.is_spendable]
        token_opts = [{"value": t.token, "client": t.client.name if t.client else "—",
                       "remaining": t.remaining} for t in tokens]
    finally:
        db.close()
    return _page(request, "pc_scan.html", "pc", user, tokens=token_opts)


@app.get("/web", response_class=HTMLResponse)
async def get_web_dashboard(request: Request):
    user = require_user(request)
    db = SessionLocal()
    try:
        tokens = [t for t in store.list_tokens(db) if t.is_spendable]
        token_opts = [{"value": t.token, "client": t.client.name if t.client else "—",
                       "remaining": t.remaining} for t in tokens]
    finally:
        db.close()
    return _page(request, "web_scan.html", "web", user, tokens=token_opts)


@app.get("/risks", response_class=HTMLResponse)
async def get_risks(request: Request):
    user = require_user(request)
    return _page(request, "risks.html", "risks", user)


@app.get("/reports", response_class=HTMLResponse)
async def get_reports(request: Request):
    user = require_user(request)
    return _page(request, "reports.html", "reports", user)


# ===================== clients (admin) =====================

@app.get("/clients", response_class=HTMLResponse)
async def clients_page(request: Request, error: str = "", ok: str = ""):
    user = require_admin_page(request)
    db = SessionLocal()
    try:
        clients = store.list_clients(db)
        rollup = {r["client_id"]: r for r in store.scans_by_client(db)}
        rows = [{
            "id": c.id, "name": c.name, "contact": c.contact, "notes": c.notes,
            "created_at": c.created_at,
            "scan_count": rollup.get(c.id, {}).get("scan_count", 0),
            "token_count": len(c.tokens),
        } for c in clients]
    finally:
        db.close()
    return _page(request, "clients.html", "clients", user,
                 clients=rows, error=error, ok=ok)


@app.post("/clients")
async def create_client(request: Request, name: str = Form(...),
                        contact: str = Form(""), notes: str = Form("")):
    require_admin_page(request)
    name = name.strip()
    if not name:
        return RedirectResponse("/clients?error=Client+name+is+required", status_code=303)
    db = SessionLocal()
    try:
        if db.query(store.Client).filter(store.Client.name == name).first():
            return RedirectResponse("/clients?error=A+client+with+that+name+already+exists",
                                    status_code=303)
        store.create_client(db, name, contact, notes)
    finally:
        db.close()
    return RedirectResponse("/clients?ok=Client+created", status_code=303)


# ===================== tokens (admin) =====================

@app.get("/tokens", response_class=HTMLResponse)
async def tokens_page(request: Request, error: str = "", ok: str = ""):
    user = require_admin_page(request)
    db = SessionLocal()
    try:
        clients = [{"id": c.id, "name": c.name} for c in store.list_clients(db)]
        tokens = store.list_tokens(db)
        rows = []
        for t in tokens:
            last = store.token_usage(db, t.id)
            last_use = None
            if last:
                lu = last[0]
                op = db.query(User).filter(User.id == lu.operator_id).first()
                last_use = {"by": op.username if op else "unknown",
                            "target": lu.target, "at": lu.created_at}
            rows.append({
                "id": t.id, "token": t.token,
                "client": t.client.name if t.client else "—",
                "limit": t.scan_limit, "uses": t.uses, "remaining": t.remaining,
                "active": t.is_active, "spendable": t.is_spendable,
                "created_at": t.created_at, "last_use": last_use,
            })
    finally:
        db.close()
    return _page(request, "tokens.html", "tokens", user,
                 clients=clients, tokens=rows, error=error, ok=ok)


@app.post("/tokens")
async def generate_token(request: Request, client_id: int = Form(...),
                         scan_limit: int = Form(...)):
    user = require_admin_page(request)
    if not client_id:
        return RedirectResponse("/tokens?error=Choose+a+client", status_code=303)
    if scan_limit < 1:
        return RedirectResponse("/tokens?error=Scan+limit+must+be+at+least+1", status_code=303)
    db = SessionLocal()
    try:
        if not store.get_client(db, client_id):
            return RedirectResponse("/tokens?error=Unknown+client", status_code=303)
        tok = store.generate_token(db, client_id, scan_limit, user.id)
        value = tok.token
    finally:
        db.close()
    return RedirectResponse(f"/tokens?ok=Generated+{value}", status_code=303)


@app.post("/tokens/{token_id}/revoke")
async def revoke_token(request: Request, token_id: int):
    require_admin_page(request)
    db = SessionLocal()
    try:
        store.revoke_token(db, token_id)
    finally:
        db.close()
    return RedirectResponse("/tokens?ok=Token+revoked", status_code=303)


# ===================== admin: users =====================

@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(request: Request, error: str = "", ok: str = ""):
    user = require_admin_page(request)
    db = SessionLocal()
    try:
        users = [{"id": u.id, "username": u.username, "full_name": u.full_name,
                  "role": u.role, "is_active": u.is_active, "created_at": u.created_at,
                  "has_2fa": bool(u.totp_secret), "is_2fa_exempt": bool(u.is_2fa_exempt)}
                 for u in store.list_users(db)]
    finally:
        db.close()
    return _page(request, "admin_users.html", "users", user,
                 users=users, error=error, ok=ok,
                 min_password_len=MIN_PASSWORD_LEN)


@app.post("/admin/users")
async def admin_create_user(request: Request, username: str = Form(...),
                            password: str = Form(...), full_name: str = Form(""),
                            role: str = Form("analyst")):
    require_admin_page(request)
    username = username.strip()
    role = role if role in ("admin", "analyst") else "analyst"
    if not username or len(password) < MIN_PASSWORD_LEN:
        return RedirectResponse(
            f"/admin/users?error=Username+required+and+password+must+be+{MIN_PASSWORD_LEN}%2B+characters",
            status_code=303)
    db = SessionLocal()
    try:
        if store.get_user_by_username(db, username):
            return RedirectResponse("/admin/users?error=That+username+is+taken",
                                    status_code=303)
        db.add(User(username=username, full_name=(full_name or None),
                    password_hash=auth.hash_password(password), role=role, is_active=True))
        db.commit()
    finally:
        db.close()
    return RedirectResponse("/admin/users?ok=Account+created", status_code=303)


@app.post("/admin/users/{user_id}/reset-2fa")
async def admin_reset_2fa(request: Request, user_id: int):
    """Clear a user's TOTP secret so they re-enroll on next login (lost device)."""
    admin = require_admin_page(request)
    db = SessionLocal()
    try:
        target = db.query(User).filter(User.id == user_id).first()
        if not target:
            return RedirectResponse("/admin/users?error=No+such+user", status_code=303)
        if target.is_2fa_exempt:
            return RedirectResponse(
                "/admin/users?error=The+break-glass+account+does+not+use+2FA",
                status_code=303)

        target.totp_secret = None
        target.totp_last_counter = None
        target.totp_failures = 0
        db.commit()
        print(f"[audit] 2FA reset for '{target.username}' by '{admin.username}' at {_now()}",
              flush=True)
        username = target.username
    finally:
        db.close()
    return RedirectResponse(
        f"/admin/users?ok=2FA+reset+for+{username}.+They+will+re-enroll+at+next+sign-in.",
        status_code=303)


@app.get("/admin/network", response_class=HTMLResponse)
def network_discovery_page(request: Request):
    user = require_admin_page(request)
    with SessionLocal() as db:
        runs = db.query(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(20).all()
        return _page(request, "network.html", "network", user, runs=runs,
                     enabled=os.getenv("NETWORK_DISCOVERY_ENABLED", "0") == "1",
                     ranges=os.getenv("NETWORK_DISCOVERY_CIDRS", ""))


@app.post("/api/discovery", status_code=202)
def start_discovery(request: Request, tasks: BackgroundTasks,
                    user: User = Depends(require_admin_api)):
    _check_csrf(request)
    from scripts import discover_network
    try:
        run_id = discover_network.enqueue()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if run_id is None:
        raise HTTPException(status_code=409, detail="Discovery is already queued or running.")
    tasks.add_task(discover_network.run, run_id=run_id)
    logging.getLogger(__name__).info("Discovery requested run=%s admin=%s", run_id, user.id)
    return {"run_id": run_id}


# ===================== scans (login + token required) =====================

@app.post("/scan")
def create_scan(request: ScanRequest, user: User = Depends(require_user_api)):
    # Sync def on purpose: the scan is fully blocking (nmap subprocess, DB, and the
    # LLM HTTP call). FastAPI runs sync path operations in a threadpool, so a long
    # scan does not freeze the worker's event loop — the gunicorn liveness heartbeat
    # keeps firing and other requests stay served. Declaring this async would block
    # the single UvicornWorker loop for minutes and trip a spurious WORKER TIMEOUT.
    _validate_token(request.token)  # fail before doing expensive work

    try:
        raw_scan = run_scan(request.target)
        scan_result = parse_scan_result(raw_scan)
    except Exception as e:
        if "Nmap error" in str(e) or "not installed" in str(e).lower():
            raise HTTPException(status_code=500, detail="Nmap not installed or error executing.")
        raise HTTPException(status_code=422, detail=f"Host not reachable or scan failed: {e}")

    db = SessionLocal()
    try:
        version = request.version or detected_product_version(scan_result, request.vendor, request.product)
        cves = find_cves(db, request.vendor, request.product, version=version)
    finally:
        db.close()

    llm_analysis = analyze_vulnerabilities(scan_result, cves)

    scan_id = str(uuid.uuid4())
    final_report = format_report_data(scan_id, scan_result, cves, llm_analysis)

    _finalize_scan(final_report, "pc", request.token, user)
    reports_db[scan_id] = final_report
    return final_report


@app.post("/scan-web")
def create_web_scan(request: WebScanRequest, user: User = Depends(require_user_api)):
    # Sync def on purpose — same reason as /scan: blocking scan work runs in the
    # threadpool so it doesn't stall the event loop / worker heartbeat.
    _validate_token(request.token)

    try:
        raw = run_web_scan(request.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Target not reachable or scan failed: {e}")

    parsed = parse_web_result(raw)
    web_findings = run_passive_checks(parsed)

    db = SessionLocal()
    try:
        cves = []
        seen = set()
        for vendor, product in banner_to_targets(parsed):
            for cve in find_cves(db, vendor, product, version=banner_version(parsed, vendor, product)):
                if cve["cve_id"] not in seen:
                    seen.add(cve["cve_id"])
                    cves.append(cve)
    finally:
        db.close()

    llm_analysis = analyze_web_vulnerabilities(parsed, web_findings, cves)

    scan_id = str(uuid.uuid4())
    final_report = format_web_report_data(scan_id, parsed, web_findings, cves, llm_analysis)

    _finalize_scan(final_report, "web", request.token, user)
    web_reports_db[scan_id] = final_report
    return final_report


# ===================== sync (login required) =====================

@app.post("/sync")
async def trigger_sync(background_tasks: BackgroundTasks, user: User = Depends(require_user_api)):
    def run_sync():
        db = SessionLocal()
        try:
            sync_cves(db)
        finally:
            db.close()

    background_tasks.add_task(run_sync)
    return {"message": "Full NVD sync started in the background."}


# A sync killed mid-run (host shutdown, OOM, SIGKILL) never reaches the except
# block in sync.nvd_sync that would mark it "failed", so its row stays "running"
# forever. Reporting the newest row unconditionally then shows a phantom sync in
# progress for good. A real sync takes ~10 minutes, so anything still "running"
# after this long was abandoned. Age is the discriminator: filtering out
# "running" rows outright would hide a genuinely in-flight sync instead.
STALLED_SYNC_AFTER = timedelta(hours=1)


def _sync_is_stalled(started_at: str | None) -> bool:
    """True if a still-"running" sync row is old enough to be considered abandoned.

    ``started_at`` is a String column holding an ISO timestamp. An unparseable or
    missing value means we cannot prove the sync is live, so treat it as stalled.
    """
    if not started_at:
        return True
    try:
        started = datetime.fromisoformat(started_at)
    except ValueError:
        return True
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - started > STALLED_SYNC_AFTER


@app.get("/sync/status")
async def get_sync_status(user: User = Depends(require_user_api)):
    db = SessionLocal()
    try:
        log = db.query(SyncLog).order_by(SyncLog.id.desc()).first()
        if not log:
            return {"status": "No sync has been run yet"}
        status = log.status
        if status == "running" and _sync_is_stalled(log.started_at):
            status = "interrupted (no result recorded; the sync did not finish)"
        return {
            "status": status,
            "started_at": log.started_at,
            "finished_at": log.finished_at,
            "records_added": log.records_added,
            "records_updated": log.records_updated,
        }
    finally:
        db.close()


# ===================== risk status / scan APIs (login required) =====================

@app.post("/api/risk-status")
async def set_risk_status(req: RiskStatusRequest, user: User = Depends(require_user_api)):
    """Mark a finding as accepted (acknowledged / won't-fix / false positive) or reopen it."""
    db_map = reports_db if req.scan_type == "pc" else web_reports_db
    report = db_map.get(req.scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    matched = 0
    new_status = "accepted" if req.accepted else "open"
    for f in report.get("findings", []):
        if str(f.get("cve_id")) == req.cve_id:
            f["status"] = new_status
            matched += 1
    if not matched:
        raise HTTPException(status_code=404, detail="Finding not found in scan")

    _recount(report)

    # keep the persisted copy in sync with the accept/undo decision
    db = SessionLocal()
    try:
        row = db.query(store.Scan).filter(store.Scan.scan_id == req.scan_id).first()
        if row:
            import json
            row.payload = json.dumps(report)
            row.critical_count = report["critical_count"]
            row.high_count = report["high_count"]
            db.commit()
    finally:
        db.close()

    return {
        "ok": True,
        "status": new_status,
        "critical_count": report["critical_count"],
        "high_count": report["high_count"],
    }


@app.get("/api/scans")
async def list_scans(user: User = Depends(require_user_api)):
    return JSONResponse(content={"scans": list(reports_db.values())})


@app.get("/api/web-scans")
async def list_web_scans(user: User = Depends(require_user_api)):
    return JSONResponse(content={"scans": list(web_reports_db.values())})


@app.get("/api/scans-by-client")
async def api_scans_by_client(user: User = Depends(require_user_api)):
    db = SessionLocal()
    try:
        return JSONResponse(content={"clients": store.scans_by_client(db)})
    finally:
        db.close()


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str, request: Request, user: User = Depends(require_admin_api)):
    """Hard-delete a scan: evict it from the in-memory cache and the DB. Admin only.

    scan_ids are unique across host and web scans, so we check both caches and the
    single persisted row. 404 only if the id is unknown everywhere.
    """
    _check_csrf(request)

    db = SessionLocal()
    try:
        in_db = store.delete_scan(db, scan_id)
    finally:
        db.close()

    # Never evict a report before its database transaction succeeds.
    in_cache = reports_db.pop(scan_id, None) is not None
    in_cache = web_reports_db.pop(scan_id, None) is not None or in_cache

    if not in_cache and not in_db:
        raise HTTPException(status_code=404, detail="Scan not found")

    logging.getLogger(__name__).info("Scan deleted scan=%s admin=%s", scan_id, user.id)
    return {"ok": True}


# ===================== reports (login required) =====================

@app.get("/report/{scan_id}")
async def get_report_json(scan_id: str, user: User = Depends(require_user_api)):
    if scan_id not in reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    return reports_db[scan_id]


@app.get("/report/{scan_id}/html", response_class=HTMLResponse)
async def get_report_html(request: Request, scan_id: str):
    user = require_user(request)
    if scan_id not in reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    return templates.TemplateResponse(
        request=request, name="report.html",
        context={"report": reports_db[scan_id], "active": "reports", "user": user},
    )


@app.get("/report/{scan_id}/pdf")
async def get_report_pdf(request: Request, scan_id: str):
    require_user(request)
    if scan_id not in reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    pdf_bytes = build_pdf(reports_db[scan_id], scan_type="host")
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="vulnsense-host-{scan_id}.pdf"'},
    )


@app.get("/web-report/{scan_id}")
async def get_web_report_json(scan_id: str, user: User = Depends(require_user_api)):
    if scan_id not in web_reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    return web_reports_db[scan_id]


@app.get("/web-report/{scan_id}/html", response_class=HTMLResponse)
async def get_web_report_html(request: Request, scan_id: str):
    user = require_user(request)
    if scan_id not in web_reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    return templates.TemplateResponse(
        request=request, name="web_report.html",
        context={"report": web_reports_db[scan_id], "active": "reports", "user": user},
    )


@app.get("/web-report/{scan_id}/pdf")
async def get_web_report_pdf(request: Request, scan_id: str):
    require_user(request)
    if scan_id not in web_reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    pdf_bytes = build_pdf(web_reports_db[scan_id], scan_type="web")
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="vulnsense-web-{scan_id}.pdf"'},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
