import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Any

def scrape_cves(vendor: str, product: str, pages: int = 1) -> List[Dict[str, Any]]:
    """
    Scrape OpenCVE for CVEs matching a vendor and product.
    Used as a fallback if NVD API is unreachable or rate limited.
    """
    results = []
    
    for page in range(1, pages + 1):
        url = f"https://app.opencve.io/cve/?vendor={vendor}&product={product}&page={page}"
        try:
            # Adding a user-agent to avoid simple blocks
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            cve_rows = soup.find_all('tr')
            for row in cve_rows:
                cols = row.find_all('td')
                if not cols or len(cols) < 5:
                    continue
                    
                cve_link = cols[0].find('a')
                if not cve_link or 'CVE-' not in cve_link.text:
                    continue
                    
                cve_id = cve_link.text.strip()
                
                cvss_text = cols[1].text.strip()
                cvss_score = 0.0
                try:
                    cvss_score = float(cvss_text.split()[0])
                except ValueError:
                    pass
                
                severity = "UNKNOWN"
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                elif cvss_score > 0:
                    severity = "LOW"
                    
                description = cols[2].text.strip()
                published_date = cols[3].text.strip()
                
                results.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "published_date": published_date
                })
                
        except Exception as e:
            print(f"Error scraping OpenCVE: {e}")
            break
            
    return results
