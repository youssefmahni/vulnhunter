from modules.base import BaseScanner
import ssl
import socket
from urllib.parse import urlparse

class SSLCheckScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Checking SSL/TLS on {self.target_url}")
        
        domain = urlparse(self.target_url).netloc
        if not domain:
            print("[!] Invalid domain for SSL check")
            return
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    print(f"[+] SSL Version: {ssock.version()}")
                    print(f"[+] Cipher: {cipher[0]}")
                    
                    if ssock.version() in ['TLSv1', 'TLSv1.1']:
                        self.add_vulnerability(
                            "Weak TLS Version",
                            f"Server supports {ssock.version()}",
                            "Medium"
                        )
                    
                    # Certificate info
                    issuer = cert.get('issuer')
                    if issuer:
                        self.add_vulnerability(
                            "Certificate Issuer",
                            f"Issuer: {issuer}",
                            "Info"
                        )
                        
        except Exception as e:
            print(f"[!] SSL Error: {e}")