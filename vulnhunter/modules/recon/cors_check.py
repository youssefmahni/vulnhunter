from modules.base import BaseScanner

class CORSCheckScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Checking CORS configuration on {self.target_url}")
        
        try:
            response = self.session.get(self.target_url)
            cors_header = response.headers.get('Access-Control-Allow-Origin')
            
            if cors_header:
                if cors_header == '*':
                    self.add_vulnerability(
                        "CORS Misconfiguration",
                        "Access-Control-Allow-Origin set to '*'",
                        "Medium"
                    )
                else:
                    print(f"[+] CORS Origin: {cors_header}")
            else:
                print("[+] No CORS header found")
                
            # Test with Origin header
            test_response = self.session.get(self.target_url, headers={'Origin': 'https://evil.com'})
            test_cors = test_response.headers.get('Access-Control-Allow-Origin')
            if test_cors == 'https://evil.com':
                self.add_vulnerability(
                    "CORS Misconfiguration",
                    "Allows arbitrary origin",
                    "High"
                )
                
        except Exception as e:
            print(f"[!] Error checking CORS: {e}")