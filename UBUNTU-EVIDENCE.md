# Local Ubuntu evidence

From the installed application's directory, a trusted Ubuntu operator can run:

    .venv/bin/python -m scripts.ubuntu_evidence

This prints JSON only. To record it, add `--record-for-client ID` with an existing organization's numeric ID; use the installed service account and its database configuration. The command prints the new report ID after commit. Authorized members can read it at `GET /api/ubuntu-evidence/{scan_id}`; the asset and scan ID appear in the scoped inventory/history APIs. No scheduled job or remote agent is installed. Stored evidence is retained like other saved scans; treat it as sensitive inventory.

Scope: current kernel hardlink/symlink protections (expected value 1), and installed versions for five named Debian packages. Unavailable package records, permission failures and timeouts do not prove absence or compliance. Versions alone do not prove a CVE. Containers and WSL may reflect host kernel policy. Inventory uses the local hostname; an application-specific machine identifier helps distinguish reinstalls during retests. Neither is proof of physical device identity.
