# Milestone 2: application-level organization isolation

The FastAPI console now filters report queries in PostgreSQL using the signed-in user's current role and memberships. The authoritative organization is the scan row's client_id, never a URL parameter or value in report JSON. Host/web lists, client totals, JSON, HTML, PDF and risk decisions use this boundary. Private pages and downloads request no browser/proxy caching.

| Account | Access |
| --- | --- |
| Platform admin | All records, including unassigned legacy reports. Sole authority to create/revoke organization assignments and delete reports. |
| Analyst | Only assigned organizations. May see their spendable tokens and submit assessments or edit risk decisions in scope. No assignment means no customer data. |
| Customer | Read-only access to reports for one explicit organization. No token list, assessment submission, risk edits or admin operations. |

## Staged rollout

1. Back up the database and rehearse restoring it on a separate Ubuntu host. Record counts of users, clients and scans, including scans with a NULL client_id. Retain the previous package and settings.
2. Keep ingress restricted to internal operators. At startup the existing schema initializer creates two additive tables: client_memberships (user/client key) and membership_events (grant/revoke journal). It does not infer ownership or alter existing report payloads. Reconcile the recorded counts.
3. In the backend console's **Accounts** page create customer accounts with the Customer role. Use **Organization access** to grant or revoke access for a customer or analyst. A customer cannot receive a second organization before the first is revoked. Repeated identical requests are no-ops. Existing analysts start with no assignments.
4. Sign in as two test customers. Verify each sees only its organization's totals and reports, foreign report IDs return 404 in every download format, and revoking the assignment immediately denies the next request. A downloaded copy cannot be revoked.
5. **Rollback:** restrict customer access first. The old application does not recognize these permissions. Disable customer accounts and block external ingress before reverting binaries; reassess analyst access as well. Do not expose the old shared console to those users. Retain membership data for forward recovery.

This is application-enforced, not PostgreSQL row-level security; the service database role remains trusted. The journal records membership changes, not every platform event, and is not tamper-proof against database administrators. No change to the sample dashboard or discovery scheduling. A production backup/restore rehearsal, database role hardening and a separately approved Ubuntu release are still required before customer-facing deployment.

The integration suite requires TEST_DATABASE_URL to point to a PostgreSQL database named vulnsense_test. It creates a unique schema inside a transaction and rolls back after each test; no scanner or external target is contacted. Run python -m pytest -q tests/test_customer_isolation.py from the application root.
