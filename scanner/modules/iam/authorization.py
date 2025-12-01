from scanner.modules.base import BaseScanner

class AuthZScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.log(f"[*] Starting Authorization Checks on {self.target_url}")
        
        # 1. Heuristic: Check for ID-related parameters in URL
        target_urls = urls or [self.target_url]
        
        import re
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        id_patterns = [
            r'id', r'user', r'account', r'order', r'invoice', r'profile', r'uid', r'pid'
        ]
        
        for url in target_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param, values in params.items():
                # Check if parameter name looks like an ID
                if any(re.search(p, param, re.IGNORECASE) for p in id_patterns):
                    for value in values:
                        # Check if value is numeric
                        if value.isdigit():
                            self.log(f"[*] Found potential IDOR parameter '{param}' with value '{value}' in {url}")
                            
                            # 2. Active Verification: Try ID-1 and ID+1
                            original_id = int(value)
                            test_ids = [str(original_id - 1), str(original_id + 1)]
                            
                            for test_id in test_ids:
                                # Construct new URL
                                new_params = params.copy()
                                new_params[param] = [test_id]
                                new_query = urlencode(new_params, doseq=True)
                                new_url = urlunparse(parsed._replace(query=new_query))
                                
                                try:
                                    res = self.session.get(new_url)
                                    
                                    if res.status_code == 200:
                                        self.add_vulnerability(
                                            "Potential IDOR",
                                            f"Access successful with modified ID ({test_id}) for parameter '{param}' at {new_url}",
                                            "High",
                                            url=new_url
                                        )
                                        self.log(f"[!] Potential IDOR confirmed at {new_url}")
                                except Exception:
                                    pass
