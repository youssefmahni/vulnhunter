from scanner.modules.base import BaseScanner

class AuthZScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Authorization Checks on {self.target_url}")
        
        # IDOR Check (Heuristic)
        # Look for numeric IDs in URLs
        target_urls = urls or [self.target_url]
        
        for url in target_urls:
            if any(char.isdigit() for char in url):
                # Very simple heuristic
                if 'id=' in url or '/user/' in url:
                     self.add_vulnerability(
                        "Potential IDOR",
                        f"URL contains numeric ID, potential for IDOR: {url}",
                        "Low",
                        url=url
                    )
