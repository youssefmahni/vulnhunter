import requests
from scanner.core.config import ConfigManager

class Requester:
    def __init__(self):
        self.config = ConfigManager()
        self.session = requests.Session()
        self.timeout = self.config.get('target.timeout', 10)
        self.session.headers.update({
            'User-Agent': 'AllSafe-Scanner/1.0'
        })

    def get(self, url, **kwargs):
        try:
            return self.session.get(url, timeout=self.timeout, **kwargs)
        except Exception as e:
            print(f"[!] Error connecting to {url}: {e}")
            return None

    def post(self, url, data=None, **kwargs):
        try:
            return self.session.post(url, data=data, timeout=self.timeout, **kwargs)
        except Exception as e:
            print(f"[!] Error posting to {url}: {e}")
            return None
