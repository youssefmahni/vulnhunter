import urllib.parse
from modules.base import BaseScanner

class OpenRedirectScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Testing for Open Redirects at {self.target_url}")
        
        payloads = self.load_list("wordlists/open_redirect_payloads.txt")
        if not payloads:
            self.logger.error("No open redirect payloads found.")
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
                    new_query = parsed.query.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    # Also handle case where we just append or replace
                    # A robust way is to rebuild the query
                    
                    # Simple replacement for now, assuming single value
                    target_url = url.replace(parsed.query, new_query)
                    
                    # Or better: use urllib to reconstruct
                    query_dict = params.copy()
                    query_dict[param] = [payload]
                    new_query_str = urllib.parse.urlencode(query_dict, doseq=True)
                    target_url = urllib.parse.urlunparse(parsed._replace(query=new_query_str))

                    try:
                        # Don't follow redirects automatically to check the Location header
                        response = self.session.get(target_url, allow_redirects=False, timeout=5)
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if payload in location:
                                self.add_vulnerability(
                                    "Open Redirect",
                                    f"Open Redirect found at {target_url} (redirects to {location})",
                                    "Medium"
                                )
                                # Stop testing this parameter if vuln found
                                break
                    except Exception as e:
                        # self.logger.debug(f"Error checking {target_url}: {e}")
                        pass
