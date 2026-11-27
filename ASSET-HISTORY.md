# Organization-scoped asset history

New host and website reports are indexed in the same database transaction as the report. After upgrading the schema, index historical reports locally with `python -m scripts.backfill_assets`. Rerunning this command is safe. Reports with an unusable identity are skipped, not merged into an "unknown" asset. Removing a scan removes its observation. Inventory lists include only assets with remaining observations.

Host identities use normalized DNS/IP. Websites use the HTTP(S) origin (scheme, canonical host and effective port), not page paths, query strings or embedded credentials. Host and web assessments are separate kinds; this is a history of reported endpoints, not proof that an IP still belongs to the same physical device.

Authenticated routes:

- GET /api/assets?limit=50 (use returned next as after for the next page).
- GET /api/assets/{id}/history (offset, limit): report IDs, recorded timestamps, observed service/product versions and findings. Uncertain candidates are counted separately. Missing observations are not resolved findings.
- PUT /api/assets/{id}/labels: replace owner, tags and exposure. Requires scoped operator/admin and session token. Exposure defaults to unknown; it is not inferred from DNS.

NVD sync retains available CWE identifiers and HTTPS vendor advisory references as it processes records. Existing unchanged records are not enriched until seen by sync. Current reference data is separate from the historical observation.

On the Ubuntu host import reviewed complete [CISA KEV JSON](https://github.com/cisagov/kev-data) and [FIRST EPSS daily CSV](https://www.first.org/epss/data.html) snapshots:

    python -m scripts.import_intelligence KEV /path/to/known_exploited_vulnerabilities.json
    python -m scripts.import_intelligence EPSS /path/to/epss_scores-current.csv.gz

These are explicit local imports, not automatic downloads. The caller is responsible for obtaining authentic complete files. Each import atomically replaces one source and refuses malformed, empty, or older data. A missing source means unavailable, not zero risk. KEV/EPSS include an as-of date and a seven-day freshness indicator; neither validates exploitation on an asset.
