# RC9: manual batch default-login checks

Network discovery keeps subnet scanning and its output, with a separate
Default-login checks area. Press **Check discovered devices** to start checks for
the displayed source scan. This admin action is the explicit trigger; no extra
approval checkbox, device selector or profile selector is required.

The batch includes every discovered IP in the latest completed or partial subnet
scan, including devices skipped by its eight-device vulnerability-assessment cap.
It does not discover additional hosts. Use a fresh subnet scan after network or
DHCP changes. Device types are not excluded. Devices without usable profiles or
supported HTTPS Basic authentication are reported unsupported/inconclusive;
this is not evidence that their passwords are secure.

The server re-reads model identity and automatically matches administrator-reviewed
profiles. At most three distinct configured credential pairs are checked per IP.
Only an unambiguous rejection allows the next pair. Success, lockout/rate limits,
TLS failures and inconclusive responses stop attempts. Duplicate credentials are
not retried. There are no bundled password lists or AI-generated credentials.

The existing `DEVICE_AUDIT_ENABLED`, `NETWORK_DISCOVERY_ENABLED`,
`NETWORK_DISCOVERY_CIDRS`, `DEVICE_AUDIT_PROFILE_FILE`, optional
`DEVICE_AUDIT_CA_BUNDLE`, and profile credential environment variables apply.
See device-audit-rc8.md for the reviewed HTTPS Basic profile format. This change
does not add form-login, SSH, HTTP-only or vendor-specific adapters.

## Persistence and operational limits

- Admin session, CSRF and an explicit batch request from the button are required. Subnet scans,
  page loads, timers and refreshes never initiate login attempts.
- Unique `DeviceAudit` keys reserve each IP before network work. Attempt slots
  are saved before each check. Repeat batches and concurrent workers cannot
  reopen an IP reservation. Older one-attempt records remain blocked as well.
- Three is a maximum, not a promise to try three times. The reservation is
  lifetime per IP, including failures and crashes; it is not reset per scan.
- One batch runs at a time with a PostgreSQL advisory lock. Unexpected process
  termination leaves queued/running batches blocked for administrator review;
  there is no automatic restart/resume or UI reset of credential budgets.
- Batches have a 15-minute processing budget, checked between devices. Remaining
  devices appear as not checked, rather than silently disappearing. An in-flight
  device check may finish after that deadline.
- Results persist incrementally in the existing `device_audits` JSON column;
  no schema migration or additional dependency is required. Refresh to see progress.
- Attempt details show profile ID, username, result and whether credential
  transmission was confirmed. Passwords are never saved in audit results or
  rendered in the page. Older results show missing metadata as not recorded;
  reserved/interrupted attempts show transmission as unconfirmed.
- A batch marked completed means processing finished, not that every login was
  attempted. Inspect each device's result and attempt count.

Live device compatibility must be validated with authorized lab devices and
reviewed profiles. Automated regression tests use synthetic devices, not live logins.
