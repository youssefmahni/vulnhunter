from modules.base import BaseScanner
import urllib.parse

class SSRFScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Testing for SSRF vulnerabilities at {self.target_url}")
        
        payloads = self.load_list("wordlists/ssrf_payloads.txt")
        if not payloads:
            self.logger.error("No SSRF payloads found.")
            return

        # Test URLs with parameters
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            if not parsed.query:
                continue
            
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                for payload in payloads:
                    # Construct new URL with payload
                    query_dict = params.copy()
                    query_dict[param] = [payload]
                    new_query_str = urllib.parse.urlencode(query_dict, doseq=True)
                    target_url = urllib.parse.urlunparse(parsed._replace(query=new_query_str))

                    try:
                        response = self.session.get(target_url, timeout=5)
                        
                        # Check for indicators
                        # This is tricky without an out-of-band interaction server (like Burp Collaborator)
                        # We look for error messages or content changes that suggest the server tried to fetch the resource
                        
                        if "root:x:0:0" in response.text or "[boot loader]" in response.text:
                             self.add_vulnerability(
                                "SSRF",
                                f"SSRF (Local File Inclusion) found at {target_url}",
                                "High"
                            )
                             break
                        
                        # Heuristic: if response time is significantly higher for internal IPs, it might be trying to connect
                        # But for now, we stick to content checks or specific error messages
                        if "Connection refused" in response.text or "Network is unreachable" in response.text:
                             self.add_vulnerability(
                                "SSRF",
                                f"Potential SSRF (Error Message) found at {target_url}",
                                "Medium"
                            )
                             break

                    except Exception as e:
                        pass
