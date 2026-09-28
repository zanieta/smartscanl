import nmap
from typing import Dict, Any

def run_scan(target: str, os_detection: bool = True) -> Dict[str, Any]:
    """
    Run an Nmap service/version scan, with optional OS detection.

    OS detection (-O) needs root/administrator. If it's requested but the
    privilege isn't available, we automatically retry without -O so the scan
    still succeeds (service/version detection only) instead of failing.
    """
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        # Raised by PortScanner() when the nmap binary isn't found on PATH
        raise Exception("nmap not installed or not on PATH")

    base_args = "-sV -Pn"  # -Pn: don't skip hosts that block ping
    args = f"{base_args} -O" if os_detection else base_args

    try:
        nm.scan(target, arguments=args)
    except nmap.PortScannerError as e:
        # -O commonly fails without admin/root — retry once without it
        if "-O" in args:
            try:
                nm.scan(target, arguments=base_args)
            except nmap.PortScannerError as e2:
                raise Exception(f"Nmap error: {e2}")
        else:
            raise Exception(f"Nmap error: {e}")
    except Exception as e:
        raise Exception(f"Scan failed: {e}")

    return nm[target] if target in nm.all_hosts() else {}
