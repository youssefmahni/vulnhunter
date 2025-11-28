from scanner.modules.base import BaseScanner

class HeaderScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Security Headers Analysis on {self.target_url}")
        
        try:
            response = self.session.get(self.target_url)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': "Missing X-Frame-Options header (Clickjacking risk)",
                'Content-Security-Policy': "Missing CSP header (XSS risk)",
                'X-Content-Type-Options': "Missing X-Content-Type-Options header (MIME sniffing risk)",
                'Strict-Transport-Security': "Missing HSTS header (MITM risk)",
                'Referrer-Policy': "Missing Referrer-Policy header"
            }
            
            for header, msg in security_headers.items():
                if header not in headers:
                    self.add_vulnerability(
                        "Missing Security Header",
                        msg,
                        "Low"
                    )
                else:
                    print(f" - Found {header}: {headers[header]}")
                    
        except Exception as e:
            print(f"[!] Error scanning headers: {e}")
