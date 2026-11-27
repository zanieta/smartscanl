# Local Ubuntu evidence

From the installed application's directory, a trusted Ubuntu operator can run:

    .venv/bin/python -m scripts.ubuntu_evidence

This prints JSON only. To record it, add `--record-for-client ID` with an existing organization's numeric ID; use the installed service account and its database configuration. The command prints the new report ID after commit. Authorized members can read it at `GET /api/ubuntu-evidence/{scan_id}`; the asset and scan ID appear in the scoped inventory/history APIs. No scheduled job or remote agent is installed. Stored evidence is retained like other saved scans; treat it as sensitive inventory.

Scope: current kernel hardlink/symlink protections (expected value 1), and installed versions for five named Debian packages. Unavailable package records, permission failures and timeouts do not prove absence or compliance. Versions alone do not prove a CVE. Containers and WSL may reflect host kernel policy. Inventory uses the local hostname; an application-specific machine identifier helps distinguish reinstalls during retests. Neither is proof of physical device identity.

Use `GET /api/ubuntu-evidence/{scan_id}/review` for normalized control observations and counts. An observed 0 opens a configuration finding, not a CVE. Missing, contradictory or duplicate records are not assessed. Each identifiable case is scoped to one organization, hostname, installation, policy version and control; a rename or reinstall deliberately breaks continuity. Records are observations, not independent validation or a claim that the rest of the machine is secure.

### Manual remediation and retest

For a deviation, the Ubuntu administrator should confirm the running setting on the system that owns the kernel, note the current value and where persistent policy is managed, and back up that configuration. Test the expected value of 1 in staging: applications relying on legacy link handling in shared writable directories may behave differently. Apply the change using your approved configuration system in a change window. If a workload breaks, restore the saved policy and previous running value via the same system and document the exception. The collector never changes kernel settings.

Record a fresh observation, then request `GET /api/ubuntu-retest?scan_id=BASELINE&scan_id=RETEST` in your authenticated session. Supply 2–16 IDs in chronological order. An observed deviation followed by a measured pass verifies resolution of **that control at that time**. A later deviation after resolution is marked reopened if that evidence is included. A partial observation cannot verify resolution. The result includes the supporting scan IDs; it does not change tickets, establish independent verification or describe observations omitted from the comparison.

### Finding-only downloads

Use `GET /api/ubuntu-evidence/{scan_id}/export/{format}` with `pdf`, `xlsx`, `csv` or `json`. Only measured deviations are exported. The raw report and scoped review retain coverage information; zero exported rows does not mean the entire host passed. Downloads omit host and installation identifiers and raw inventory. XLSX uses the pinned XlsxWriter dependency in requirements.txt.
