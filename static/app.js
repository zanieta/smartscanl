/* SmartScan shared client helpers — normalizes host + web scans into one shape.
   The `window.VulnSense` global is kept as-is: it's an internal identifier used by
   ~30 call sites across the templates, not a name any user sees. */
window.VulnSense = (function () {
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
    function cap(s) {
        s = String(s || '');
        return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
    }

    async function loadAllScans() {
        const out = [];
        try {
            const host = await (await fetch('/api/scans')).json();
            (host.scans || []).forEach(s => out.push({
                ...s,
                type: 'PC',
                label: s.host || 'Unknown host',
                subLabel: 'OS: ' + (s.os || 'Unknown'),
                reportUrl: `/report/${s.scan_id}/html`,
                pdfUrl: `/report/${s.scan_id}/pdf`,
            }));
        } catch (e) { /* endpoint may be empty */ }
        try {
            const web = await (await fetch('/api/web-scans')).json();
            (web.scans || []).forEach(s => out.push({
                ...s,
                type: 'WEB',
                label: s.url || s.host || 'Unknown site',
                subLabel: s.server || 'Web target',
                reportUrl: `/web-report/${s.scan_id}/html`,
                pdfUrl: `/web-report/${s.scan_id}/pdf`,
            }));
        } catch (e) { /* endpoint may be empty */ }
        return out;
    }

    function isAccepted(f) { return String(f && f.status || '').toLowerCase() === 'accepted'; }

    // The bucket a finding counts toward: accepted findings leave their severity.
    function bucketOf(f) { return isAccepted(f) ? 'accepted' : String(f.severity || '').toLowerCase(); }

    // Tally findings across scans into the 5 severity buckets.
    function tally(scans) {
        const c = { critical: 0, high: 0, medium: 0, low: 0, accepted: 0 };
        scans.forEach(s => (s.findings || []).forEach(f => { const b = bucketOf(f); if (b in c) c[b]++; }));
        return c;
    }

    // Persist an accept/undo decision to the server.
    async function setRiskStatus(scanType, scanId, cveId, accepted) {
        const res = await fetch('/api/risk-status', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_type: scanType === 'PC' ? 'pc' : 'web', scan_id: scanId, cve_id: cveId, accepted })
        });
        return res.ok;
    }

    // Map a severity to a 0-3 threat level for the signal-bar meter.
    function threatBars(sev) {
        const k = String(sev || '').toLowerCase();
        const lv = (k === 'critical' || k === 'high' || k === 'medium' || k === 'low') ? k : 'low';
        return `<span class="threat lv-${lv}" title="${cap(lv)}"><i></i><i></i><i></i><i></i></span>`;
    }

    return { esc, cap, loadAllScans, threatBars, isAccepted, bucketOf, tally, setRiskStatus };
})();
