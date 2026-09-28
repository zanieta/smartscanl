from typing import Dict, Any

def parse_scan_result(raw_result: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes raw nmap result dict into a clean JSON structure."""
    if not raw_result:
        return {"host": "Unknown", "os": "Unknown", "open_ports": [], "services": []}
        
    host = raw_result.get('addresses', {}).get('ipv4', 'Unknown')
    if host == 'Unknown':
        host = raw_result.get('hostnames', [{'name': 'Unknown'}])[0].get('name', 'Unknown')
    
    # Extract OS if available
    os_name = "Unknown"
    if 'osmatch' in raw_result and len(raw_result['osmatch']) > 0:
        os_name = raw_result['osmatch'][0].get('name', 'Unknown')
        
    open_ports = []
    services = []
    
    if 'tcp' in raw_result:
        for port, port_info in raw_result['tcp'].items():
            if port_info.get('state') == 'open':
                open_ports.append(port)
                
                service_name = port_info.get('name', '')
                service_product = port_info.get('product', '')
                service_version = port_info.get('version', '')
                
                service_desc = f"{service_name} {service_product} {service_version}".strip()
                
                services.append({
                    "port": port,
                    "service": service_desc,
                    "product": service_product,
                    "version": service_version,
                    "cpe": port_info.get('cpe', ''),
                })
                
    return {
        "host": host,
        "os": os_name,
        "open_ports": open_ports,
        "services": services
    }


def detected_product_version(scan: dict, vendor: str, product: str) -> str | None:
    """Only associate versions through an exact CPE identity, not fuzzy banners."""
    versions = set()
    for service in scan.get('services', []):
        cpes = service.get('cpe', [])
        if isinstance(cpes, str):
            cpes = [cpes]
        for cpe in cpes or []:
            parts = cpe.split(':')
            offset = 3 if cpe.startswith('cpe:2.3:') else 2
            if len(parts) <= offset + 2:
                continue
            if parts[offset:offset + 2] != [vendor.lower(), product.lower()]:
                continue
            version = parts[offset + 2]
            if version not in ('', '*', '-'):
                versions.add(version)
    return next(iter(versions)) if len(versions) == 1 else None
