from scanner.modules.base import BaseScanner

class CommandInjectionScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Command Injection Scan on {self.target_url}")
        
        payloads = ["; cat /etc/passwd", "| cat /etc/passwd", "`cat /etc/passwd`"]
        
        target_forms = forms or []
        for form in target_forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            for payload in payloads:
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
                        
                    if "root:x:0:0" in res.text:
                         self.add_vulnerability(
                            "Command Injection",
                            f"Command Injection found at {action} with payload: {payload}",
                            "Critical",
                            url=action
                        )
                         print(f"[!] Command Injection found at {action}")
                except Exception:
                    pass
