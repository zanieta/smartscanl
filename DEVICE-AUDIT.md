# RC8 patch: controlled device audits

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
