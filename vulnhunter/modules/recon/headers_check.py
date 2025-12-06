from modules.base import BaseScanner

class HeadersCheckScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Checking security headers on {self.target_url}")
        
        try:
            response = self.session.get(self.target_url)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': "Missing X-Frame-Options (Clickjacking risk)",
                'Content-Security-Policy': "Missing CSP (XSS risk)",
                'X-Content-Type-Options': "Missing X-Content-Type-Options (MIME sniffing risk)",
                'Strict-Transport-Security': "Missing HSTS (MITM risk)",
                'Referrer-Policy': "Missing Referrer-Policy",
                'X-XSS-Protection': "Missing X-XSS-Protection"
            }
            
            for header, msg in security_headers.items():
                if header not in headers:
                    self.add_vulnerability(
                        "Missing Security Header",
                        msg,
                        "Low"
                    )
                else:
                    self.logger.success(f"Found {header}")
                    
        except Exception as e:
            self.logger.error(f"Error checking headers: {e}")