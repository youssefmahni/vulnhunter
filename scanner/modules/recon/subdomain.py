from scanner.modules.base import BaseScanner
from scanner.core.config import ConfigManager
import requests
from urllib.parse import urlparse

class SubdomainScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Subdomain Enumeration on {self.target_url}")
        
        domain = urlparse(self.target_url).netloc
        if not domain:
            print("[!] Invalid target URL for subdomain enumeration.")
            return

        # Passive Enumeration using crt.sh
        print(f"[*] Querying crt.sh for {domain}...")
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name_value = entry['name_value']
                    for sub in name_value.split('\n'):
                        subdomains.add(sub)
                
                print(f"[*] Found {len(subdomains)} subdomains (Passive):")
                for sub in sorted(subdomains):
                    print(f" - {sub}")
                    self.add_vulnerability(
                        "Subdomain Found (Passive)",
                        f"Found subdomain: {sub}",
                        "Info",
                        url=f"http://{sub}"
                    )
            else:
                print(f"[!] crt.sh returned status code {response.status_code}")
        except Exception as e:
            print(f"[!] Error querying crt.sh: {e}")

        # Active Enumeration (Brute Force) - Placeholder for now as per plan
        # We can implement this using the wordlist from config
