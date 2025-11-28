from scanner.modules.base import BaseScanner
from scanner.core.config import ConfigManager
import os

class DirectoryBruteScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Directory Brute-forcing on {self.target_url}")
        
        config = ConfigManager()
        wordlist_path = config.get('wordlists.directories')
        
        if not wordlist_path or not os.path.exists(wordlist_path):
            print(f"[!] Wordlist not found: {wordlist_path}")
            return

        print(f"[*] Using wordlist: {wordlist_path}")
        
        try:
            with open(wordlist_path, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
                
            for path in paths:
                url = f"{self.target_url.rstrip('/')}/{path}"
                try:
                    response = self.session.get(url, timeout=config.get('target.timeout', 10))
                    if response.status_code in [200, 301, 302, 403]:
                        print(f" - Found: {url} (Status: {response.status_code})")
                        self.add_vulnerability(
                            "Directory Discovered",
                            f"Found directory/file: {path} (Status: {response.status_code})",
                            "Info",
                            url=url
                        )
                except Exception as e:
                    pass
        except Exception as e:
            print(f"[!] Error reading wordlist: {e}")
