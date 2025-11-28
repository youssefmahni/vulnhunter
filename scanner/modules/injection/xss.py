from scanner.modules.base import BaseScanner

class XSSScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting XSS Scan on {self.target_url}")
        
        payload = "<script>alert('XSS')</script>"
        
        target_forms = forms or []
        for form in target_forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            print(f" - Testing form at {action}")
            
            data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    data[name] = payload
            
            try:
                if method == 'post':
                    res = self.session.post(action, data=data)
                else:
                    res = self.session.get(action, params=data)
                    
                if payload in res.text:
                    self.add_vulnerability(
                        "Reflected XSS",
                        f"XSS Payload reflected at {action}",
                        "High",
                        url=action
                    )
                    print(f"[!] XSS found at {action}")
            except Exception:
                pass
