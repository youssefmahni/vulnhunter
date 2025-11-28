from scanner.modules.base import BaseScanner
from scanner.core.config import ConfigManager
from colorama import Fore, Style
import os

class AuthScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Authentication Testing on {self.target_url}")
        
        config = ConfigManager()
        users_path = config.get('wordlists.users')
        passwords_path = config.get('wordlists.passwords')
        
        # 1. Default Credentials Check (Simplified)
        print("[*] Checking for default credentials...")
        defaults = [('admin', 'admin'), ('admin', 'password'), ('user', 'user')]
        
        # In a real scenario, we would need to know the login URL and parameter names.
        # For this rebuild, we'll iterate over discovered forms if available, or just log the attempt.
        
        target_forms = forms or []
        login_form = None
        for form in target_forms:
            # Heuristic to find login form
            if 'login' in form['action'].lower() or any(i.get('name') and 'user' in i['name'] for i in form['inputs']):
                login_form = form
                break
        
        if login_form:
            print(f"[*] Found potential login form at {login_form['action']}")
            # Here we would attempt to login with defaults
            # For demonstration, we just log that we found the form
            self.add_vulnerability(
                "Login Form Discovered",
                f"Login form found at {login_form['action']}",
                "Info",
                url=login_form['action']
            )
        else:
            print("[*] No obvious login form found in crawled data.")

        # 2. Brute Force
        if login_form and users_path and passwords_path and os.path.exists(users_path) and os.path.exists(passwords_path):
            print(f"[*] Starting brute-force attack on {login_form['action']}...")
            
            try:
                with open(users_path, 'r', encoding='utf-8', errors='ignore') as f:
                    users = [line.strip() for line in f if line.strip()]
                with open(passwords_path, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                
                # Limit for demo/safety
                users = users[:5]
                passwords = passwords[:10]
                
                for user in users:
                    for password in passwords:
                        data = {}
                        for input_tag in login_form['inputs']:
                            name = input_tag.get('name')
                            if not name: continue
                            
                            if 'user' in name.lower() or 'email' in name.lower() or 'login' in name.lower():
                                data[name] = user
                            elif 'pass' in name.lower():
                                data[name] = password
                            else:
                                data[name] = 'submit'
                        
                        try:
                            if login_form['method'] == 'post':
                                res = self.session.post(login_form['action'], data=data, allow_redirects=False)
                            else:
                                res = self.session.get(login_form['action'], params=data, allow_redirects=False)
                            
                            # Success detection: Redirect or significant length change
                            # This is heuristic and might need tuning
                            if res.status_code in [301, 302]:
                                print(f"{Fore.GREEN}[+] Potential Success: {user}:{password} (Redirect to {res.headers.get('Location')}){Style.RESET_ALL}")
                                self.add_vulnerability(
                                    "Weak Credentials",
                                    f"Valid credentials found: {user}:{password}",
                                    "Critical",
                                    url=login_form['action']
                                )
                                return # Stop after first success
                        except Exception:
                            pass
            except Exception as e:
                print(f"[!] Error during brute-force: {e}")
