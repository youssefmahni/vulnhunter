from scanner.modules.base import BaseScanner

class WAFScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Checking for WAF on {self.target_url}")
        
        payload = "<script>alert('WAF')</script>"
        waf_signatures = {
            'Cloudflare': 'cloudflare',
            'AWS WAF': 'awselb',
            'Akamai': 'akamai',
            'F5 BIG-IP': 'big-ip',
            'Imperva': 'incapsula'
        }
        
        try:
            # 1. Active Check
            res = self.session.get(self.target_url, params={'test': payload})
            
            if res.status_code in [403, 406, 501]:
                self.add_vulnerability(
                    "WAF Detected (Active)",
                    f"WAF blocked malicious payload with status {res.status_code}",
                    "Info"
                )
                print(f"[!] WAF Detected: Blocked payload with status {res.status_code}")
            
            # 2. Passive Check (Headers)
            detected_waf = []
            headers = str(res.headers).lower()
            for name, sig in waf_signatures.items():
                if sig in headers:
                    detected_waf.append(name)
            
            if detected_waf:
                self.add_vulnerability(
                    "WAF Detected (Passive)",
                    f"WAF signatures found in headers: {', '.join(detected_waf)}",
                    "Info"
                )
                print(f"[!] WAF Detected: {', '.join(detected_waf)}")
                
        except Exception as e:
            print(f"[!] Error checking WAF: {e}")
