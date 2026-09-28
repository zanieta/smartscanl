"""Authenticated smoke test for a running SmartScan deployment.

Caveat before running this against production: reaching an authenticated page
requires a session that has cleared the second factor, and the only account that
can do that unattended is the 2FA-exempt break-glass user. Every use of it emits
an `[audit] BREAK-GLASS LOGIN` line (main.py), so running this on a schedule
turns the one alert that account exists to raise into routine noise. It also
requires BREAKGLASS_PASSWORD to still be present in .env, so a deployment that
deliberately removed it will fail this check rather than pass it.

For unattended production monitoring, prefer the unauthenticated checks here
plus `python -m scripts.update_cves --check-only`; keep the break-glass path for
deliberate post-deploy verification.
"""

import argparse
import sys
import time

import httpx
from dotenv import dotenv_values


def _wait_for_app(url: str, attempts: int) -> int:
    for _ in range(attempts):
        try:
            response = httpx.get(url, timeout=3)
            if response.status_code == 200:
                return response.status_code
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError(f"App did not become ready at {url}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--direct-url", default="http://127.0.0.1:8000")
    parser.add_argument("--base-url", default="https://127.0.0.1")
    parser.add_argument("--attempts", type=int, default=20)
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS verification for the local self-signed certificate")
    args = parser.parse_args()

    config = dotenv_values(args.env_file)
    username = config.get("ADMIN_USERNAME")
    password = config.get("ADMIN_PASSWORD")
    breakglass_username = config.get("BREAKGLASS_USERNAME")
    breakglass_password = config.get("BREAKGLASS_PASSWORD")
    if not username or not password:
        print("ADMIN_USERNAME and ADMIN_PASSWORD must be set in the environment file.",
              file=sys.stderr)
        return 2
    if not breakglass_username or not breakglass_password:
        print("BREAKGLASS_USERNAME and BREAKGLASS_PASSWORD must be set in the environment file.",
              file=sys.stderr)
        return 2

    try:
        direct_status = _wait_for_app(f"{args.direct_url.rstrip('/')}/login", args.attempts)
        with httpx.Client(base_url=args.base_url, verify=not args.insecure,
                          follow_redirects=False, timeout=10) as client:
            login_page = client.get("/login")
            # A fresh admin has no TOTP secret yet, and this deployment
            # enforces mandatory enrollment: a correct login redirects to
            # /2fa/enroll rather than logging the admin straight in. Checking
            # the redirect *target*, not just the 303 status, matters -- a
            # rejected login never produces a 303 to /2fa/enroll, so this
            # still fails on bad credentials.
            admin_login = client.post("/login", data={"username": username, "password": password})
            logo = client.get("/static/logo.png")

        # The break-glass account is 2FA-exempt by design, precisely so
        # there is a way to reach an authenticated page without an
        # authenticator. A separate client/session keeps this login from
        # clobbering the admin session above, and it's what lets this test
        # make the check it always intended to make -- that a genuinely
        # authenticated request reaches home -- now that the admin path
        # alone stops short of full authentication until enrolled.
        with httpx.Client(base_url=args.base_url, verify=not args.insecure,
                          follow_redirects=False, timeout=10) as bg_client:
            breakglass_login = bg_client.post(
                "/login", data={"username": breakglass_username, "password": breakglass_password})
            home = bg_client.get("/")
    except (httpx.HTTPError, RuntimeError) as exc:
        print(f"Smoke test failed: {exc}", file=sys.stderr)
        return 1

    checks = {
        "direct login page": direct_status == 200,
        "nginx login page": login_page.status_code == 200,
        # Accept EITHER second-factor destination. main.py:203 sends a user with
        # no TOTP secret to /2fa/enroll and an already-enrolled one to
        # /2fa/verify, so pinning /2fa/enroll would pass only on a brand-new
        # deployment and fail forever after the admin enrols — the same
        # fresh-install assumption that made the previous `GET / == 200` check
        # stale. Either destination proves the same two things: the password was
        # accepted, and a second factor is being demanded. A 303 back to /login
        # means the credentials were rejected and must still fail.
        "login demands a second factor": (
            admin_login.status_code == 303
            and admin_login.headers.get("location") in ("/2fa/enroll", "/2fa/verify")
        ),
        "breakglass authenticated home": (
            breakglass_login.status_code == 303 and home.status_code == 200
        ),
        "static logo": logo.status_code == 200,
    }
    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
