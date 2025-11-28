from scanner.modules.base import BaseScanner

class TechStackScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Tech Stack Fingerprinting on {self.target_url}")
        
        try:
            response = self.session.get(self.target_url)
            headers = response.headers
            
            technologies = []
            
            if 'Server' in headers:
                technologies.append(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                technologies.append(f"X-Powered-By: {headers['X-Powered-By']}")
            if 'X-AspNet-Version' in headers:
                technologies.append(f"ASP.NET Version: {headers['X-AspNet-Version']}")
            
            # Simple HTML checks
            if 'wp-content' in response.text:
                technologies.append("CMS: WordPress")
            if 'drupal' in response.text.lower():
                technologies.append("CMS: Drupal")
            
            if technologies:
                print(f"[*] Identified Technologies:")
                for tech in technologies:
                    print(f" - {tech}")
                    self.add_vulnerability(
                        "Technology Discovered",
                        f"Identified technology: {tech}",
                        "Info"
                    )
            else:
                print("[*] No specific technologies identified from headers/body.")
                
        except Exception as e:
            print(f"[!] Error fingerprinting tech stack: {e}")
