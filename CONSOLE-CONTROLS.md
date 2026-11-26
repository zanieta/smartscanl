# Milestone 1: internal console access

Scope: one trusted internal workspace. A client ID is attribution, not a permission grant. Do not expose this as a customer portal; tenant separation is milestone 2.

| Action | Allowed identity | Request contract |
| --- | --- | --- |
| Read login; submit credentials | Anonymous | GET issues form token; POST requires it. Only known internal destinations are accepted after login. |
| Enroll or verify second factor | Password-verified pending session | POST form token; pending is not a logged-in operator. |
| Sign out | Current session (including pending) | POST with form token. GET does not change the session. |
| Read dashboard, host/web scan forms, risk and report lists, HTML/JSON/PDF reports, CVE status and client rollup | Signed-in internal operator | Read-only within the shared internal workspace. |
| Start host/website assessment; accept or reopen finding | Signed-in internal operator | JSON request plus session token header; starting assessments still requires a spendable scan token. |
| Manage clients, scan tokens, accounts and second-factor resets | Platform admin | Protected pages; write forms require session token. Newly issued token values are not placed in redirect URLs. |
| Network admin pages and network assessment exports | Platform admin | Page-role check; network scope controls unchanged. |
| Start manual CVE sync; delete scan; request existing device/network operations | Platform admin | Authenticated API and session token header; existing operation-specific authorization still applies. |

Browser clients receive a CSRF token from the rendered page. Submit it as the csrf_token form field or X-CSRF-Token request header. Keep the same cookie session; retrieve a fresh token after authentication or a transition into the pending second-factor state. Reload an old tab if its request is rejected. Existing API clients posting without this token must be updated. The scheduled CVE updater does not call the web endpoint and is unchanged.

No schema or service changes. For acceptance, run python -m pytest -q tests/test_console_controls.py from the repository root with the application/test dependencies installed. Tests use local mock storage; they do not perform scans, send credentials to devices or refresh CVE data.
