from scanner.modules.base import BaseScanner

class HeaderScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        target_urls = urls if urls else [self.target_url]
        
        for url in target_urls:
            try:
                response = self.session.get(url)
                headers = response.headers
                
                security_headers = [
                    'X-Frame-Options',
                    'Content-Security-Policy',
                    'X-Content-Type-Options',
                    'Strict-Transport-Security'
                ]
                
                for header in security_headers:
                    if header not in headers:
                        self.add_vulnerability(
                            "Missing Security Header",
                            f"Header {header} is missing.",
                            "Low",
                            url=url
                        )
            except Exception as e:
                print(f"Error scanning headers for {url}: {e}")
