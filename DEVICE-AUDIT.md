# RC8 patch: controlled device audits

Current RC9 batch behavior is documented in [device-login-rc9.md](device-login-rc9.md).
The selector-based RC9 UI description below is historical and superseded by that
batch workflow; the profile format and HTTPS validation requirements still apply.

## RC9 UI addition: Default-login checks

The network page retains the subnet scan controls and scan output, and adds a
separate Default-login checks area. It lists devices from the latest 20 subnet
scan records, filtered against the current approved scope, alongside reviewed
login profile IDs/models only. Credentials and environment-variable values never
enter the page. Historical addresses may be reassigned; operators must confirm
the selected device before authorizing a check. The existing checker re-reads
the model before any credential-bearing request.

No login check runs on page load, refresh or subnet scanning. Each submission
requires administrator authentication, CSRF validation and explicit approval.
The persistent one-attempt-per-IP limit remains enforced by PostgreSQL. Used
targets are disabled in the selector, including interrupted checks. The most
recent 20 login results appear with recommendations. A rejected credential is
not proof of a changed password. Unsupported/inconclusive results are not findings.

Configure `DEVICE_AUDIT_ENABLED=1`, approved network scope, and
`DEVICE_AUDIT_PROFILE_FILE` with the reviewed profiles and server-side credential
environment variables described below. Missing profiles disable the form. Invalid
configuration shows a sanitized message without preventing subnet scanning.
This UI adds no vendor adapters or bundled passwords: HTTPS Basic-auth profiles
remain the only supported login mechanism. No new database schema is required
beyond the audit/workflow tables introduced earlier. RC9 has not been published
by adding this section; release packaging is a separate step.

## Local subnet workflow (October 14)

The subnet workflow retains Scan local subnets and Local network scans. Legacy
standalone identification controls and discovery output remain removed; RC9 adds
the separate login area described above. Existing records and protected backend
endpoints remain intact.
Device identification runs inside the subnet workflow; its optional profile
setting is collapsed by default.

The Network discovery page now offers approved subnet checkboxes and an optional
comma-separated narrower CIDR input. Narrower CIDRs replace the checkbox selection.
Neither input can expand `NETWORK_DISCOVERY_CIDRS`; only server-approved RFC1918
IPv4 scope is accepted (at most four nonoverlapping /24-or-smaller subnets).
The scanner runs from the installed server, not the administrator's browser.

`Discover devices` performs discovery only on the selection. `Scan selected
subnets` requires explicit approval for active service probes and runs discovery,
device identification, service/CVE assessment and recommendations in sequence.
No scheduled trigger, exploit scripts or credential attempts are added. Existing
DEVICE_AUDIT_ENABLED controls optional HTTPS model/firmware extraction; service
identification still runs when HTTPS identity extraction is disabled or unavailable.

The initial bounds are eight responding devices per run, top 100 TCP ports,
light service/version detection, a 60-second process timeout per device, and a
15-minute budget checked between devices. Discovery can take 90 seconds per
subnet. A current bounded operation may finish after the overall budget expires.
Skipped devices are explicitly listed; select a smaller subnet for another batch.
Jobs share the discovery PostgreSQL advisory lock. Duplicate work is rejected;
queued/running workflow records older than 30 minutes are marked interrupted when
another workflow is requested. Process restarts do not resume probes automatically.

Only explicit versioned service CPEs are matched (maximum 20 product identities,
up to 50 CVE candidates per identity). Part, vendor, product and version must
match local database criteria. Uncertain, contextual, legacy-metadata and excluded
matches are not reported as vulnerabilities. Firmware labels alone are NOT mapped
to CVEs. No model-to-CPE guessing or AI inference is performed.

Reports reuse the normal host report/PDF format, with deterministic vendor-oriented
recommendations. They are stored in the additive `network_scan_runs` table and
available to administrators from the network page, independently of PC scan
history. Per-device identity, source evidence, stage, completion status and coverage
are retained. Risk-acceptance controls are not offered on these immutable reports.
Empty databases, unsupported CPEs, timeouts and skipped devices are shown as
unassessed/partial, never as secure. Monitor database size and back up this history;
automatic retention/deletion is not implemented for network workflow reports.

Installation/update startup creates the new table through `init_db`; no existing
tables or environment settings are removed. Use the backed-up updater. Test the
flow on a small authorized subnet first. Unit and browser fixtures are not a
replacement for real-device acceptance testing.

This patch adds separate admin actions to Network discovery. Discovery remains
manual-only and never attempts login. No photos, AI guesses or online model lookup
are needed. No vendor login profiles are shipped: real device support must be
verified before configuring one.

## Enable on Ubuntu

Use the normal backed-up updater. Startup creates the additive `device_audits`
table; existing scan data is unchanged. Preserve this table across upgrades: it
contains the persistent login-attempt budget. Restoring an older database can
restore an older budget, so do not repeat checks after a rollback.

In the existing server environment, set `DEVICE_AUDIT_ENABLED=1`. Discovery must
also be enabled with explicitly approved `NETWORK_DISCOVERY_CIDRS`. Restart the
application after changing its environment. Existing installers preserve `.env`,
so upgrading alone does not enable these actions.

Identification reads only HTTPS port 443 at the literal approved IPv4 address.
Certificates must validate, including the IP address. For a private CA, set
`DEVICE_AUDIT_CA_BUNDLE` to its PEM bundle. TLS verification cannot be bypassed.
HTTP-only devices, JavaScript-only interfaces, untrusted certificates and missing
explicit fields are unsupported. Model/firmware values are device-reported, not
independently authenticated. Unknown or conflicting fields remain Unknown.

## Optional reviewed login profiles

Set `DEVICE_AUDIT_PROFILE_FILE` to an administrator-owned JSON list outside the
repository, readable by the app but not writable by it. Each record has:

- `id`: lowercase letters, digits and hyphens, at most 64 characters.
- `model`: exact observed model, 3–100 characters.
- `reviewed`: true only after administrator verification against vendor guidance.
- `source_url`: HTTPS vendor reference (recorded, not automatically fetched).
- `proof_path`: read-only HTTPS Basic-auth endpoint, using letters/digits/slashes,
  underscores or hyphens only. No configuration-changing endpoint.
- `proof_marker`: 12–200 character marker found only after successful authentication.
- `username_env` and `password_env`: environment-variable names prefixed
  `DEVICE_DEFAULT_`, followed by uppercase letters, digits or underscores.

Configure the documented default credentials in those server environment
variables; never commit them. There is deliberately no built-in admin/admin list.
An administrator must select the reviewed profile and approve each check in the
UI. The code first confirms the model and a 401 Basic-auth baseline without the
proof marker, then sends at most one credential-bearing request. No redirects,
proxies, password lists, retries, form logins or SSH are used. Responses are bounded
to 64 KiB with connect/read timeouts and a response-time budget.

One login check per IP is reserved in PostgreSQL before network access, across
workers and restarts. Failures consume this budget; no UI reset exists. Identification
is limited to once per IP per UTC minute. Lockout signals stop checks, but even a
single attempt can cause lockout. Rejection does not establish that credentials
were changed. Unsupported or inconclusive results are not vulnerabilities.

The latest 20 audit results are shown separately from historical discovery
snapshots. Raw pages and credentials are not stored. Do not delete audit rows to
retry. Plan retention and database backups with the persistent budget in mind.

## Verification scope

### Identification profile framework (October 12)

An optional `DEVICE_IDENTITY_PROFILE_FILE` points to a separate administrator-owned
JSON list. Each profile contains `id`, `reviewed`, `source_url`, `path`, `format`
(`json` or `xml`), expected `manufacturer`, and `fields`. Fields map `manufacturer`,
`model`, optional `firmware` and `device_type` to slash-separated paths, e.g.
`device/model`. JSON paths traverse objects only; XML paths include the root and
match local tag names, including namespaced documents. No XPath, regex extraction,
scripts, attributes, external entities or arbitrary code are supported.

Manufacturer and model paths are required. Conflicting values remain Unknown;
a manufacturer mismatch discards the entire identity. Field-level evidence records
the extracted value, selector and endpoint. The source URL is an operator reference,
not proof of independent vendor validation. HTML without a profile also supports
explicit manufacturer and device-type labels.

Enter the reviewed ID in the identification form to perform one unauthenticated
GET to that profile's approved read-only endpoint. Blank uses the existing HTML
root-page parser. There is no automatic endpoint sweep or fallback. Identification
profiles cannot enable login checks or bypass their fresh model check. Historical
results appear in a dated table, separately from discovery snapshots to avoid
incorrectly joining devices after DHCP reassignment. No new database migration
is needed beyond the RC8.1 audit table.

No vendor-specific profiles have yet been validated or bundled. This is a parser
framework, not a claim that every manufacturer exposes these endpoints. Firmware
behind authentication and browser-only applications remain unsupported.

Automated tests use synthetic HTTPS responses and a test PostgreSQL database.
They do not establish support for any specific router, camera, phone or firmware.
Real-device validation and an operator-reviewed vendor profile remain necessary
before using the login check in production.
