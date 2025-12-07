from modules.base import BaseScanner
import requests

class XXEScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Testing for XXE vulnerabilities at {self.target_url}")
        
        payloads = self.load_list("wordlists/xxe_payloads.txt")
        if not payloads:
            self.logger.error("No XXE payloads found.")
            return

        # Focus on forms for now, as they are the most likely place to inject XML
        for form in forms:
            action = form.get('action')
            if not action:
                continue
                
            # Try to inject into each input field
            for inp in form.get('inputs', []):
                name = inp.get('name')
                if not name:
                    continue
                
                for payload in payloads:
                    data = {}
                    # Fill other fields with dummy data
                    for other_inp in form.get('inputs', []):
                        other_name = other_inp.get('name')
                        if other_name:
                            data[other_name] = "test"
                    
                    # Inject payload
                    data[name] = payload
                    
                    try:
                        # Test both as standard form data (some apps might parse it)
                        # and potentially as raw XML if we were more advanced.
                        # For now, just standard POST with payload in field.
                        response = self.session.post(action, data=data, timeout=5)
                        
                        # Check for success indicators
                        if "root:x:0:0" in response.text or "[boot loader]" in response.text:
                            self.add_vulnerability(
                                "XXE Injection",
                                f"XXE vulnerability found at {action} in parameter '{name}'",
                                "High"
                            )
                            return # Stop if found
                            
                    except Exception as e:
                        # self.logger.debug(f"Error checking {action}: {e}")
                        pass
