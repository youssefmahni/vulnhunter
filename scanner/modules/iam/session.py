from scanner.modules.base import BaseScanner

class SessionScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.log(f"[*] Starting Session Management Analysis on {self.target_url}")
        
        try:
            response = self.session.get(self.target_url)
            cookies = response.cookies
            
            if not cookies:
                self.log("[*] No cookies set by the server.")
                return
                
            for cookie in cookies:
                self.log(f" - Analyzing cookie: {cookie.name}")
                
                if not cookie.secure:
                    self.add_vulnerability(
                        "Insecure Cookie",
                        f"Cookie {cookie.name} missing Secure flag",
                        "Medium"
                    )

                if 'httponly' not in str(cookie._rest).lower() and not cookie.has_nonstandard_attr('HttpOnly'):
                    self.add_vulnerability(
                        "Insecure Cookie",
                        f"Cookie {cookie.name} missing HttpOnly flag",
                        "Medium"
                    )

        except Exception as e:
            self.log(f"[!] Error analyzing sessions: {e}")
