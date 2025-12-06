from modules.base import BaseScanner
import os

class BruteForceScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Testing brute force on login forms at {self.target_url}")

        if not forms:
            return

        users = self.load_list("wordlists/users.txt")
        passwords = self.load_list("wordlists/passwords.txt")

        for form in forms:
            if self.is_login_form(form):
                action = form.get('action')
                if not action:
                    continue
                for user in users[:5]:  # Limit
                    for pwd in passwords[:5]:
                        data = {}
                        for inp in form['inputs']:
                            name = inp.get('name')
                            if not name:
                                continue
                            if 'user' in name.lower() or 'email' in name.lower():
                                data[name] = user
                            elif 'pass' in name.lower():
                                data[name] = pwd

                        response = self.session.post(action, data=data)
                        if self.is_successful_login(response):
                            self.add_vulnerability(
                                "Weak Credentials",
                                f"Login successful with {user}:{pwd} on {action}",
                                "High"
                            )
                            break
                    else:
                        continue
                    break
    
    def is_login_form(self, form):
        inputs = [inp['name'].lower() for inp in form['inputs'] if inp['name']]
        return 'user' in ' '.join(inputs) or 'pass' in ' '.join(inputs)
    
    def is_successful_login(self, response):
        # Simple check: no redirect to login or error message
        if not response or not response.url:
            return False
        return response.status_code == 200 and 'login' not in response.url.lower()
    
    def load_list(self, path):
        if os.path.exists(path):
            with open(path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return ["admin", "test"]