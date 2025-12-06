from modules.base import BaseScanner
import os

class SQLIScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Testing SQL Injection on {self.target_url}")
        
        payloads = self.load_payloads("wordlists/sqli_payloads.txt")
        
        if forms:
            for form in forms:
                action = form['action']
                for payload in payloads[:10]:  # Limit for demo
                    data = {inp['name']: payload for inp in form['inputs'] if inp['name']}
                    response = self.session.post(action, data=data)
                    if self.detect_sqli(response):
                        self.add_vulnerability(
                            "SQL Injection",
                            f"Form at {action} vulnerable to SQLi with payload: {payload}",
                            "High"
                        )
                        break
        
        # Test URLs
        if urls:
            for url in urls:
                for payload in payloads[:5]:
                    test_url = f"{url}?id={payload}"
                    response = self.session.get(test_url)
                    if self.detect_sqli(response):
                        self.add_vulnerability(
                            "SQL Injection",
                            f"URL {test_url} vulnerable to SQLi",
                            "High"
                        )
                        break
    
    def load_payloads(self, path):
        if os.path.exists(path):
            with open(path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return ["' OR '1'='1", "1' OR '1'='1' --"]
    
    def detect_sqli(self, response):
        # Simple detection: look for SQL errors
        errors = ["sql syntax", "mysql_fetch", "ORA-", "SQLite"]
        return any(error in response.text.lower() for error in errors)