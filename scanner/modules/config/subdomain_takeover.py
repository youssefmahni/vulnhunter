from scanner.modules.base import BaseScanner
from urllib.parse import urlparse
import socket

class SubdomainTakeoverScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Subdomain Takeover Check on {self.target_url}")
        
        domain = urlparse(self.target_url).netloc
        
        signatures = {
            "NoSuchBucket": "AWS S3",
            "The specified bucket does not exist": "AWS S3",
            "There is isn't a GitHub Pages site here": "GitHub Pages",
            "Heroku | No such app": "Heroku"
        }
        
        try:
            # Check CNAME (simplified)
            # In a real tool, we'd use dnspython to check CNAME records
            response = self.session.get(self.target_url)
            for sig, service in signatures.items():
                if sig in response.text:
                    self.add_vulnerability(
                        "Subdomain Takeover",
                        f"Potential takeover on {service}",
                        "High"
                    )
                    print(f"[!] Potential {service} takeover detected!")
        except Exception as e:
            pass
