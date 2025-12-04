from modules.base import BaseScanner

class WAFDetectScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Detecting WAF on {self.target_url}")
        
        payload = "<script>alert('WAF')</script>"
        waf_signatures = {
            'Cloudflare': ['cloudflare', '__cfduid'],
            'AWS WAF': ['awselb'],
            'Akamai': ['akamai'],
            'F5 BIG-IP': ['big-ip', 'f5'],
            'Imperva': ['incapsula'],
            'ModSecurity': ['mod_security']
        }
        
        try:
            # Active check
            res = self.session.get(self.target_url, params={'test': payload})
            
            if res.status_code in [403, 406, 501]:
                self.add_vulnerability(
                    "WAF Detected (Active)",
                    f"WAF blocked payload with status {res.status_code}",
                    "Info"
                )
                return True  # WAF detected
            
            # Passive check
            headers = str(res.headers).lower()
            detected = []
            for name, sigs in waf_signatures.items():
                for sig in sigs:
                    if sig in headers:
                        detected.append(name)
                        break
            
            if detected:
                self.add_vulnerability(
                    "WAF Detected (Passive)",
                    f"WAF signatures: {', '.join(detected)}",
                    "Info"
                )
                return True
            
            return False  # No WAF
            
        except Exception as e:
            print(f"[!] Error detecting WAF: {e}")
            return False