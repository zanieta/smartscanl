import os
import time
import requests
from typing import List, Dict, Any

def lookup_cves(vendor: str, product: str) -> List[Dict[str, Any]]:
    """
    Query the NVD REST API 2.0 for CVEs matching a vendor and product.
    Returns a list of parsed CVE dicts.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "virtualMatchString": f"cpe:2.3:a:{vendor}:{product}",
        "resultsPerPage": 20
    }
    
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
        
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        
        if response.status_code == 403:
            raise Exception("NVD Rate Limit")
            
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        results = []
        for v in vulnerabilities:
            cve_item = v.get("cve", {})
            cve_id = cve_item.get("id", "Unknown")
            
            descriptions = cve_item.get("descriptions", [])
            desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available")
            
            metrics = cve_item.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            if cvss_data:
                cvss_info = cvss_data[0].get("cvssData", {})
                cvss_score = cvss_info.get("baseScore", 0.0)
                severity = cvss_info.get("baseSeverity", "UNKNOWN")
            
            published_date = cve_item.get("published", "")
            
            results.append({
                "cve_id": cve_id,
                "description": desc,
                "cvss_score": cvss_score,
                "severity": severity,
                "published_date": published_date
            })
            
        if not api_key:
            time.sleep(6)
            
        return results
        
    except Exception as e:
        raise Exception(f"NVD query failed: {e}")
