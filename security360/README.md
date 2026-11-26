# DE-Webnet Security360 UI milestone

This is a standalone local preview, not a new Ubuntu installer. From this directory, with Node.js 22 LTS and npm:

    npm ci
    npm run build -- --webpack
    npm start

Open http://127.0.0.1:3060/?mode=sample for demo records. Try the Host and Website filters, then open Findings, Reports and Settings. Sample mode does not need the scanner backend. Links labelled “Open scanner” and “Manage” leave the preview for the configured console.

Live mode uses the existing internal scanner APIs and session. SECURITY360_BACKEND_URL is the trusted server-side FastAPI address; SECURITY360_CONSOLE_URL is the corresponding browser-facing console address. Both default to the local scanner on port 8766. Do not point the backend URL at an untrusted server. This preview is not a tenant-isolated customer portal.

Milestone scope: dashboard presentation and read-only report views. No backend patch, CVE refresh, database migration, scanner installation or release tag.
