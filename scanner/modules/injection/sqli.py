from scanner.modules.base import BaseScanner
from scanner.core.config import ConfigManager
import time

class SQLInjectionScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting SQL Injection Scan on {self.target_url}")
        
        config = ConfigManager()
        payloads_path = config.get('scanners.sqli.payloads')
        
        payloads = ["'", "\"", "' OR 1=1 --", "\" OR 1=1 --"]
        if payloads_path:
             # Load extra payloads if file exists (omitted for brevity)
             pass
             
        errors = ["syntax error", "mysql", "sql", "database error"]
        
        target_forms = forms or []
        for form in target_forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            print(f" - Testing form at {action}")
            
            # Baseline request for Boolean-based check
            base_len = 0
            try:
                # Create dummy data preserving input names
                dummy_data = {i.get('name'): 'test' for i in inputs if i.get('name')}
                if method == 'post':
                    base_res = self.session.post(action, data=dummy_data)
                else:
                    base_res = self.session.get(action, params=dummy_data)
                base_len = len(base_res.text)
            except:
                pass

            for payload in payloads:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload
                
                try:
                    # 1. Error-based & Boolean-based (Content Length)
                    start_time = time.time()
                    if method == 'post':
                        res = self.session.post(action, data=data)
                    else:
                        res = self.session.get(action, params=data)
                    elapsed_time = time.time() - start_time

                    # Error-based
                    for error in errors:
                        if error in res.text.lower():
                            self.add_vulnerability(
                                "SQL Injection (Error-based)",
                                f"SQL Error found at {action} with payload: {payload}",
                                "High",
                                url=action
                            )
                            print(f"[!] SQL Injection (Error-based) found at {action}")
                            break
                    
                    # Time-based Blind
                    # Heuristic: if payload suggests sleep/delay and response takes > 5s
                    if "sleep" in payload.lower() or "waitfor" in payload.lower() or "benchmark" in payload.lower():
                        if elapsed_time > 5:
                            self.add_vulnerability(
                                "SQL Injection (Time-based)",
                                f"Response delayed by {elapsed_time:.2f}s with payload: {payload}",
                                "Critical",
                                url=action
                            )
                            print(f"[!] SQL Injection (Time-based) found at {action}")

                    # Boolean-based (Content Length)
                    # Heuristic: Significant change in response length for "True" payloads
                    if base_len > 0 and abs(len(res.text) - base_len) > (base_len * 0.3):
                        if "OR 1=1" in payload:
                             self.add_vulnerability(
                                "SQL Injection (Boolean-based)",
                                f"Response length changed significantly ({len(res.text)} vs {base_len}) with payload: {payload}",
                                "Medium",
                                url=action
                            )
                             print(f"[!] SQL Injection (Boolean-based) found at {action}")

                except Exception:
                    pass
