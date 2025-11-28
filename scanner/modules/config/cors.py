from scanner.modules.base import BaseScanner

class CORSScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting CORS Misconfiguration Check on {self.target_url}")
        
        try:
            # Test 1: Reflect Origin
            origin = "http://evil.com"
            headers = {'Origin': origin}
            res = self.session.get(self.target_url, headers=headers)
            
            if res.headers.get('Access-Control-Allow-Origin') == origin:
                self.add_vulnerability(
                    "CORS Misconfiguration",
                    f"Server reflects arbitrary Origin: {origin}",
                    "High"
                )
                print(f"[!] Found CORS Reflection: {origin}")
                
            # Test 2: Null Origin
            headers = {'Origin': 'null'}
            res = self.session.get(self.target_url, headers=headers)
            if res.headers.get('Access-Control-Allow-Origin') == 'null':
                self.add_vulnerability(
                    "CORS Misconfiguration",
                    "Server allows null Origin",
                    "Medium"
                )
                print("[!] Found CORS Null Origin allowed")
                
        except Exception as e:
            print(f"[!] Error checking CORS: {e}")
