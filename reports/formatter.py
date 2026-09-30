from typing import Dict, Any, List


def partition_report(report: dict) -> dict:
    """New reports separate review-only candidates from actionable findings."""
    all_findings = report['findings']
    report['uncertain_findings'] = [f for f in all_findings if f.get('match_status') == 'uncertain']
    report['informational_findings'] = [f for f in all_findings
        if f.get('match_status') != 'uncertain' and f.get('severity') in ('Informational', 'None')]
    report['findings'] = [f for f in all_findings
        if f.get('match_status') != 'uncertain' and f.get('severity') not in ('Informational', 'None')]
    report['uncertain_count'] = len(report['uncertain_findings'])
    report['informational_count'] = len(report['informational_findings'])
    report['finding_count'] = len(report['findings'])
    report['cve_candidate_count'] = report['cves_found']
    report['cves_found'] = sum(f.get('severity_source') == 'cve_database' for f in report['findings'])
    report['critical_count'] = sum(f['severity'] == 'Critical' for f in report['findings'])
    report['high_count'] = sum(f['severity'] == 'High' for f in report['findings'])
    report['report_schema_version'] = 2
    report['assessment_note'] = ('Observed configuration findings and version-matched CVE candidates; '
        'exploitation is not confirmed. Uncertain candidates and informational notes are excluded from totals.')
    # An AI summary based on the unpartitioned list can reintroduce inflated totals.
    ai_unavailable = 'AI analysis unavailable' in report.get('summary', '')
    report['summary'] = (f"{report['finding_count']} findings for review; "
        f"{report['uncertain_count']} uncertain CVE candidates; "
        f"{report['informational_count']} informational notes. " + report['assessment_note'])
    if ai_unavailable:
        report['summary'] += ' AI analysis unavailable; deterministic checks retained.'
    report['data_warnings'] = sorted({f.get('match_reason', '') for f in report['uncertain_findings']
        if 'Legacy NVD' in f.get('match_reason', '')})
    return report


def grounded_findings(cves: list, checks: list, analysis: dict) -> list:
    """Model text can enrich evidence, but cannot add/drop findings or rate them."""
    explanations = {}
    for item in analysis.get('findings', []):
        if isinstance(item, dict) and isinstance(item.get('cve_id'), str):
            explanations.setdefault(item['cve_id'], item)
    findings = []
    seen = set()
    for source, is_cve in [(c, True) for c in cves] + [(c, False) for c in checks]:
        identifier = source.get('cve_id' if is_cve else 'id')
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        model = explanations.get(identifier, {})
        severity = str(source.get('severity') or 'Unknown').capitalize()
        if severity not in {'Critical', 'High', 'Medium', 'Low', 'None', 'Informational'}:
            severity = 'Unknown'
        description = source.get('description' if is_cve else 'title') or ''
        explanation = model.get('risk_explanation')
        fix = model.get('fix')
        findings.append({
            'cve_id': identifier, 'severity': severity,
            'severity_source': 'cve_database' if is_cve else 'scanner_rule',
            'description': description,
            'risk_explanation': explanation if isinstance(explanation, str) and explanation.strip()
                else source.get('evidence') or description,
            'fix': fix if isinstance(fix, str) and fix.strip()
                else source.get('fix') or 'Verify applicability and follow vendor remediation guidance.',
        })
    return findings


def attach_match_evidence(finding: dict, source: dict) -> None:
    if not source.get('match_status'):
        return
    for key in ('match_status', 'match_reason', 'detected_version'):
        finding[key] = source.get(key)
    # Existing HTML/PDF renderers already show this field. Keep uncertainty visible
    # even if the model omits it, and retain structured evidence in stored reports.
    note = f"CVE applicability: {source['match_status']}. {source.get('match_reason', 'Verify applicability.')}"
    finding['risk_explanation'] = note + '\n' + str(finding.get('risk_explanation', ''))

def format_report_data(scan_id: str, scan_result: Dict[str, Any], cves_found: List[Dict[str, Any]], llm_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combines all data into the final structured JSON format.
    """
    findings = grounded_findings(cves_found, [], llm_analysis)
    
    cve_dict = {cve["cve_id"]: cve for cve in cves_found}
    
    critical_count = 0
    high_count = 0
    
    for finding in findings:
        cve_id = finding.get("cve_id")
        orig_data = cve_dict.get(cve_id, {})
        attach_match_evidence(finding, orig_data)
        
        finding["cvss"] = orig_data.get("cvss_score", 0.0)
        if "description" not in finding:
            finding["description"] = orig_data.get("description", "")
            
        sev = str(finding.get("severity", "")).lower()
        if sev == "critical":
            critical_count += 1
        elif sev == "high":
            high_count += 1
            
    return partition_report({
        "scan_id": scan_id,
        "host": scan_result.get("host", "Unknown"),
        "os": scan_result.get("os", "Unknown"),
        "open_ports": scan_result.get("open_ports", []),
        "services": scan_result.get("services", []),
        "cves_found": len(cves_found),
        "critical_count": critical_count,
        "high_count": high_count,
        "summary": llm_analysis.get("summary", ""),
        "findings": findings
    })


def format_web_report_data(scan_id: str, parsed: Dict[str, Any], web_findings: List[Dict[str, Any]],
                           cves_found: List[Dict[str, Any]], llm_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Combine passive web findings + matched CVEs + LLM analysis into the report shape.

    Mirrors format_report_data but with website host fields. Findings reuse the
    same {cve_id, severity, risk_explanation, fix, cvss, description} shape so the
    report template can render them unchanged.
    """
    findings = grounded_findings(cves_found, web_findings, llm_analysis)

    cve_dict = {cve["cve_id"]: cve for cve in cves_found}
    check_dict = {f["id"]: f for f in web_findings}

    critical_count = 0
    high_count = 0

    for finding in findings:
        fid = finding.get("cve_id")
        cve_data = cve_dict.get(fid)
        check_data = check_dict.get(fid)

        if cve_data:
            attach_match_evidence(finding, cve_data)
            finding["cvss"] = cve_data.get("cvss_score", 0.0)
            if not finding.get("description"):
                finding["description"] = cve_data.get("description", "")
        else:
            finding["cvss"] = "N/A"
            if not finding.get("description"):
                finding["description"] = check_data.get("title", "") if check_data else ""

        sev = str(finding.get("severity", "")).lower()
        if sev == "critical":
            critical_count += 1
        elif sev == "high":
            high_count += 1

    tls = parsed.get("tls") or {}

    return partition_report({
        "scan_id": scan_id,
        "url": parsed.get("final_url", parsed.get("url", "Unknown")),
        "host": parsed.get("host", "Unknown"),
        "server": parsed.get("server", "Unknown"),
        "powered_by": parsed.get("powered_by", "") or "Not disclosed",
        "https": parsed.get("https", False),
        "redirects_to_https": parsed.get("redirects_to_https"),
        "status_code": parsed.get("status_code"),
        "tls_issuer": tls.get("issuer", "Unknown"),
        "tls_expiry": tls.get("not_after", "Unknown"),
        "checks_flagged": len(web_findings),
        "cves_found": len(cves_found),
        "critical_count": critical_count,
        "high_count": high_count,
        "summary": llm_analysis.get("summary", ""),
        "findings": findings
    })
