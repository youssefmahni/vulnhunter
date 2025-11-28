from scanner.modules.base import BaseScanner
from urllib.parse import urlparse

class DorkingScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Google Dorking on {self.target_url}")
        
        domain = urlparse(self.target_url).netloc
        if not domain:
            print("[!] Invalid target URL for dorking.")
            return

        dorks = [
            f"site:{domain} ext:php",
            f"site:{domain} inurl:admin",
            f"site:{domain} inurl:login",
            f"site:{domain} ext:sql",
            f"site:{domain} ext:bak",
            f"site:{domain} intitle:\"index of\""
        ]
        
        print("[*] Generated Dorks (Manual Check Recommended):")
        for dork in dorks:
            print(f" - {dork}")
            self.add_vulnerability(
                "Google Dork",
                f"Generated dork: {dork}",
                "Info"
            )
