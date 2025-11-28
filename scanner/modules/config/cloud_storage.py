from scanner.modules.base import BaseScanner
from urllib.parse import urlparse
import requests

class CloudStorageScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Cloud Storage Enumeration on {self.target_url}")
        
        domain = urlparse(self.target_url).netloc
        name = domain.split('.')[0] # Simple heuristic
        
        buckets = [
            f"http://{name}.s3.amazonaws.com",
            f"http://{name}-assets.s3.amazonaws.com",
            f"http://{name}-backup.s3.amazonaws.com",
            f"https://{name}.blob.core.windows.net/container"
        ]
        
        for bucket in buckets:
            try:
                res = requests.head(bucket, timeout=5)
                if res.status_code == 200:
                    print(f" - Found Open Bucket: {bucket}")
                    self.add_vulnerability(
                        "Open Cloud Storage",
                        f"Accessible bucket found: {bucket}",
                        "High",
                        url=bucket
                    )
                elif res.status_code == 403:
                    print(f" - Found Protected Bucket: {bucket}")
            except Exception:
                pass
