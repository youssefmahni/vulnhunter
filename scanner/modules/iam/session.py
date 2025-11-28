from scanner.modules.base import BaseScanner

class SessionScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Session Management Analysis on {self.target_url}")
        
        try:
            response = self.session.get(self.target_url)
            cookies = response.cookies
            
            if not cookies:
                print("[*] No cookies set by the server.")
                return
                
            for cookie in cookies:
                print(f" - Analyzing cookie: {cookie.name}")
                
                if not cookie.secure:
                    self.add_vulnerability(
                        "Insecure Cookie",
                        f"Cookie {cookie.name} missing Secure flag",
                        "Medium"
                    )
                
                # HttpOnly check is harder with requests.cookies as it parses them.
                # We can check the Set-Cookie header raw string.
                if 'httponly' not in str(cookie._rest).lower() and not cookie.has_nonstandard_attr('HttpOnly'):
                     # This is a bit tricky with requests, simplifying for now
                     pass

        except Exception as e:
            print(f"[!] Error analyzing sessions: {e}")
