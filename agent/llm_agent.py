import os
import json
import logging
from typing import Dict, Any, List, Literal
from pydantic import BaseModel, ConfigDict, Field, ValidationError

import requests  # used to talk to the local Ollama HTTP API

# NOTE: the Anthropic SDK is imported lazily inside _claude_chat(), not here, so a
# missing/broken anthropic install degrades one scan to the rule-based fallback
# instead of stopping the whole app from starting.

# =====================================================================
# Active provider: local Ollama (gpt-oss:latest)
# =====================================================================
# Point OLLAMA_BASE_URL at wherever Ollama listens. If Ollama runs on the same
# machine as this server, the default is fine; if it's on the GPU box, set e.g.
# OLLAMA_BASE_URL=http://192.168.68.103:11434 in .env (the box must run Ollama
# with OLLAMA_HOST=0.0.0.0 so 11434 is reachable on the LAN).
# Defaults only. The real values are read per-call inside _ollama_chat() so that
# .env (loaded at startup) always wins over any stale OS env var, regardless of
# module import order.
DEFAULT_BASE_URL = "http://localhost:11434"
# Must be a tag that exists on the Ollama host — it's only resolved when a scan
# runs, so a wrong default fails at scan time, not at startup.
DEFAULT_MODEL = "gpt-oss:latest"   # local Ollama model; overridden by OLLAMA_MODEL in .env

# =====================================================================
# Claude (Anthropic) provider — ENABLED. Selected with LLM_PROVIDER=claude in .env
# (requires ANTHROPIC_API_KEY). Used when the local Ollama box is unavailable.
# =====================================================================
CLAUDE_MODEL = "claude-sonnet-5"   # cloud model used when LLM_PROVIDER=claude; override via CLAUDE_MODEL env

# Cap how many CVEs we hand the model. Keeps the report focused and the output
# bounded so it never gets truncated mid-JSON.
MAX_FINDINGS = 20
log = logging.getLogger(__name__)


class AnalysisFinding(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    cve_id: str = Field(min_length=1)
    severity: Literal['Critical', 'High', 'Medium', 'Low', 'None', 'Informational', 'Unknown']
    risk_explanation: str = Field(min_length=1)
    fix: str = Field(min_length=1)


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    summary: str = Field(min_length=1)
    findings: List[AnalysisFinding] = Field(min_length=1, max_length=100)


ANALYSIS_SCHEMA = AnalysisResponse.model_json_schema()

SYSTEM_PROMPT = """You are a senior security analyst writing a vulnerability report for a specific scanned host.

For the CVEs provided:
1. Preserve the supplied severity exactly; do not reclassify or invent findings.
   Missing severity means Unknown. Severity is not proof of applicability.
   Keep unknown versions and uncertain matches explicitly unconfirmed.
2. For each CVE write:
   - risk_explanation: 2-4 sentences in plain language. Cover what the flaw is, the likely
     attack vector, the affected software/platforms, and the real-world impact. Be specific
     to the CVE, not generic.
   - fix: concrete, actionable remediation. Name the vendor/product, the patch or version to
     apply, and the exact command where relevant (e.g. 'apt-get upgrade linux-image-*',
     'yum update kernel', or 'apply the latest Windows cumulative update').
3. Write an executive summary of 3-5 sentences on the host's overall exposure and top priorities.

Return ONLY a raw JSON object (no markdown fences, no prose around it) in exactly this shape:
{"summary": "...", "findings": [{"cve_id": "CVE-...", "severity": "Critical", "risk_explanation": "...", "fix": "..."}]}"""


def _ollama_chat(system_prompt: str, user_prompt: str) -> str:
    """Schema-constrained Ollama call with one repair attempt for invalid output.

    Config is read fresh from the environment on every call. ``keep_alive`` is
    0 by default, so the model is loaded only for the duration of a scan and
    unloaded immediately afterwards (it never sits idle in VRAM between scans).

    Returns the model's message content (a JSON string). Raises on transport or
    HTTP errors so callers can fall back to the rule-based analysis.
    """
    base = os.getenv("OLLAMA_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    model = os.getenv("OLLAMA_MODEL", DEFAULT_MODEL)
    num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "8192"))   # small context keeps KV cache light
    timeout = int(os.getenv("OLLAMA_TIMEOUT", "300"))    # seconds; a local 14B can be slow
    keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "0")     # "0" => unload right after each scan

    payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": ANALYSIS_SCHEMA,
            "keep_alive": keep_alive,
            "options": {"num_ctx": num_ctx, "temperature": 0, "num_predict": 8192},
    }
    # At most two requests. Do not multiply transport failures with retries;
    # retry only malformed/truncated output, and never echo model text into logs.
    for attempt in range(2):
        resp = requests.post(f"{base}/api/chat", json=payload,
                             timeout=(10, min(max(timeout, 1), 120)))
        resp.raise_for_status()
        try:
            body = resp.json()
            if not isinstance(body, dict) or body.get('done_reason') == 'length':
                raise ValueError('Incomplete model output')
            content = body.get('message', {}).get('content', '')
            data = AnalysisResponse.model_validate_json(content)
            return data.model_dump_json()
        except (ValueError, TypeError, AttributeError, ValidationError):
            if attempt == 1:
                raise ValueError('AI response failed schema validation after two attempts') from None
            log.warning('Invalid Ollama response structure; retrying once')
            payload['messages'] = [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt + '\nReturn the required JSON object. '
                 'Each findings entry must be an object with cve_id, severity, risk_explanation and fix strings.'},
            ]


# --- Claude (Anthropic) provider — ACTIVE when LLM_PROVIDER=claude ----------
# Ollama (_ollama_chat above) remains the default; this is the cloud path used
# when the local model host is down. Requires ANTHROPIC_API_KEY.
def _claude_chat(system_prompt: str, user_prompt: str) -> str:
    """Single-shot Claude Messages API call, forcing JSON via the prompt."""
    from anthropic import Anthropic  # lazy: only needed when LLM_PROVIDER=claude

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    model = os.getenv("CLAUDE_MODEL", CLAUDE_MODEL)
    client = Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model,
        max_tokens=16000,  # non-streaming: stays under the SDK HTTP timeout
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    # A security tool can trip safety classifiers; treat a refusal as "no AI result".
    if resp.stop_reason == "refusal":
        raise RuntimeError("Claude declined the request (refusal)")
    if resp.stop_reason == "max_tokens":
        print("LLM warning: response hit max_tokens; consider lowering MAX_FINDINGS.")
    return next((b.text for b in resp.content if b.type == "text"), "")


def _llm_chat(system_prompt: str, user_prompt: str) -> str:
    """Route the analysis call to the configured provider.

    LLM_PROVIDER=claude uses the Anthropic Messages API (_claude_chat); anything
    else, including unset, uses the local Ollama host (_ollama_chat) as before.
    Either provider raising is caught by the caller, which then falls back to the
    rule-based analyzer, so a dead provider degrades the report rather than
    failing the scan.
    """
    provider = os.getenv("LLM_PROVIDER", "ollama").strip().lower()
    if provider == "claude":
        return _claude_chat(system_prompt, user_prompt)
    return _ollama_chat(system_prompt, user_prompt)


def _dedupe_and_rank(cve_list: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    """Drop duplicate CVE IDs (the CPE join can repeat them), rank by CVSS desc, cap to `limit`."""
    seen: Dict[str, Dict[str, Any]] = {}
    for cve in cve_list:
        cid = cve.get("cve_id")
        if cid and cid not in seen:
            seen[cid] = cve
    ranked = sorted(seen.values(), key=lambda c: c.get("cvss_score") or 0.0, reverse=True)
    return ranked[:limit]


def _extract_json(text: str) -> Dict[str, Any]:
    """Parse the model's JSON, tolerating accidental markdown fences or surrounding prose."""
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0]
    elif "```" in text:
        text = text.split("```", 2)[1]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1:
        text = text[start:end + 1]
    return json.loads(text)


def _validate_analysis(data: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure the model returned the expected {summary, findings:[{...}]} shape.

    Both providers must meet the same strict schema. Local model responses are
    also validated inside the Ollama repair loop. Error messages intentionally
    exclude model text; the caller can safely label the fallback report.
    """
    try:
        return AnalysisResponse.model_validate(data).model_dump()
    except ValidationError:
        raise ValueError('AI response does not match the required report schema') from None


def analyze_vulnerabilities(scan_result: Dict[str, Any], cve_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Use the local LLM (gpt-oss:latest via Ollama) to rank the scanned host's CVEs,
    explain each risk in plain language, and recommend a fix.
    Returns {"summary": str, "findings": [...]}. Falls back to a rule-based
    report when the model is unreachable or returns invalid JSON.
    """
    findings_input = _dedupe_and_rank(cve_list, MAX_FINDINGS)
    if not findings_input:
        return {"summary": "No known CVEs matched this host in the local database.", "findings": []}

    user_prompt = (
        f"Scan result:\n{json.dumps(scan_result)}\n\n"
        f"CVEs to analyze (top {len(findings_input)} by CVSS):\n{json.dumps(findings_input)}"
    )

    # --- Analysis via the configured provider (LLM_PROVIDER: ollama | claude) ---
    try:
        text = _llm_chat(SYSTEM_PROMPT, user_prompt)
        return _validate_analysis(_extract_json(text))
    except Exception as e:
        print(f"LLM error: {e}")
        return fallback_analysis(findings_input, error=str(e))

    # --- Claude version (commented out, kept for future use) ---
    # api_key = os.getenv("ANTHROPIC_API_KEY")
    # if not api_key:
    #     return fallback_analysis(findings_input, error="ANTHROPIC_API_KEY not set")
    # try:
    #     client = Anthropic(api_key=api_key)
    #     response = client.messages.create(
    #         model=CLAUDE_MODEL,
    #         max_tokens=16000,  # large enough for 20 detailed findings
    #         system=SYSTEM_PROMPT,
    #         messages=[{"role": "user", "content": user_prompt}],
    #     )
    #     if response.stop_reason == "max_tokens":
    #         print("LLM warning: response hit max_tokens; consider lowering MAX_FINDINGS.")
    #     text = next((b.text for b in response.content if b.type == "text"), "")
    #     return _validate_analysis(_extract_json(text))
    # except Exception as e:
    #     print(f"LLM API Error: {e}")
    #     return fallback_analysis(findings_input, error=str(e))


WEB_SYSTEM_PROMPT = """You are a senior web application security analyst writing a report for a scanned website.

You are given two inputs:
1. PASSIVE FINDINGS: misconfigurations observed from HTTP response headers, cookies, redirects, and the TLS certificate.
2. CVEs: known vulnerabilities from a local database, matched to the server software detected in the site's banners.

For every passive finding AND every CVE provided:
1. Preserve the supplied severity exactly; do not reclassify or invent findings.
   Missing severity means Unknown. Severity is not proof of applicability.
   Keep unknown versions and uncertain matches explicitly unconfirmed.
2. For each, write:
   - risk_explanation: 2-4 sentences in plain language -- what the weakness is, the likely attack vector, and the real-world impact. Be specific.
   - fix: concrete, actionable remediation (exact header, cookie flag, config change, or patch/version).
3. Write an executive summary of 3-5 sentences on the site's overall exposure and top priorities.

For passive findings use the provided check id (e.g. "WEB-HSTS") as the cve_id. For CVEs use the real CVE id.

Return ONLY a raw JSON object (no markdown fences, no prose around it) in exactly this shape:
{"summary": "...", "findings": [{"cve_id": "...", "severity": "Critical", "risk_explanation": "...", "fix": "..."}]}"""


def analyze_web_vulnerabilities(web_result: Dict[str, Any], web_findings: List[Dict[str, Any]],
                                cve_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Use the local LLM (gpt-oss:latest via Ollama) to rank + explain a website's
    passive findings and matched CVEs.

    Returns {"summary": str, "findings": [...]}. Falls back to a rule-based
    report when the model is unreachable or returns invalid JSON.
    """
    ranked_cves = _dedupe_and_rank(cve_list, MAX_FINDINGS)
    if not web_findings and not ranked_cves:
        return {"summary": "No passive misconfigurations or known CVEs were identified for this site.", "findings": []}

    site_context = {
        "url": web_result.get("final_url"),
        "server": web_result.get("server"),
        "powered_by": web_result.get("powered_by"),
        "https": web_result.get("https"),
        "tls": web_result.get("tls"),
    }

    user_prompt = (
        f"Site:\n{json.dumps(site_context)}\n\n"
        f"PASSIVE FINDINGS:\n{json.dumps(web_findings)}\n\n"
        f"CVEs (top {len(ranked_cves)} by CVSS):\n{json.dumps(ranked_cves)}"
    )

    # --- Analysis via the configured provider (LLM_PROVIDER: ollama | claude) ---
    try:
        text = _llm_chat(WEB_SYSTEM_PROMPT, user_prompt)
        return _validate_analysis(_extract_json(text))
    except Exception as e:
        print(f"LLM error (web): {e}")
        return web_fallback_analysis(web_findings, cve_list, error=str(e))

    # --- Claude version (commented out, kept for future use) ---
    # api_key = os.getenv("ANTHROPIC_API_KEY")
    # if not api_key:
    #     return web_fallback_analysis(web_findings, cve_list, error="ANTHROPIC_API_KEY not set")
    # try:
    #     client = Anthropic(api_key=api_key)
    #     response = client.messages.create(
    #         model=CLAUDE_MODEL,
    #         max_tokens=16000,
    #         system=WEB_SYSTEM_PROMPT,
    #         messages=[{"role": "user", "content": user_prompt}],
    #     )
    #     if response.stop_reason == "max_tokens":
    #         print("LLM warning: web response hit max_tokens; consider lowering MAX_FINDINGS.")
    #     text = next((b.text for b in response.content if b.type == "text"), "")
    #     return _validate_analysis(_extract_json(text))
    # except Exception as e:
    #     print(f"LLM API Error (web): {e}")
    #     return web_fallback_analysis(web_findings, cve_list, error=str(e))


def web_fallback_analysis(web_findings: List[Dict[str, Any]], cve_list: List[Dict[str, Any]],
                          error: str = "") -> Dict[str, Any]:
    """Rule-based web report used when the local model is unreachable or returns invalid JSON."""
    findings = []

    for f in web_findings:
        findings.append({
            "cve_id": f.get("id", "WEB"),
            "severity": str(f.get("severity", "Low")).capitalize(),
            "risk_explanation": f.get("evidence", f.get("title", "")),
            "fix": f.get("fix", "Review and harden this configuration."),
        })

    for cve in _dedupe_and_rank(cve_list, MAX_FINDINGS):
        findings.append({
            "cve_id": cve.get("cve_id"),
            "severity": str(cve.get("severity", "UNKNOWN")).capitalize(),
            "risk_explanation": cve.get("description", "No description available."),
            "fix": "Apply vendor updates and patches for the affected software.",
        })

    summary = "Passive web scan completed (AI analysis unavailable)."
    if error:
        summary += f" Note: AI analysis failed due to error: {error}"

    return {"summary": summary, "findings": findings}


def fallback_analysis(cve_list: List[Dict[str, Any]], error: str = "") -> Dict[str, Any]:
    """Basic non-AI analysis used when the local model is unreachable or returns invalid JSON."""
    sorted_cves = sorted(cve_list, key=lambda x: x.get("cvss_score", 0) or 0, reverse=True)

    findings = []
    for cve in sorted_cves:
        findings.append({
            "cve_id": cve.get("cve_id"),
            "severity": str(cve.get("severity", "UNKNOWN")).capitalize(),
            "risk_explanation": cve.get("description", "No description available."),
            "fix": "Apply vendor updates and patches.",
        })

    summary = "Basic automated scan completed (AI analysis unavailable)."
    if error:
        summary += f" Note: AI analysis failed due to error: {error}"

    return {"summary": summary, "findings": findings}
