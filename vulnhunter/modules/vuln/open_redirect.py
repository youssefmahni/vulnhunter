import urllib.parse
from modules.base import BaseScanner
import re

class OpenRedirectScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Testing for Open Redirects at {self.target_url}")
        
        # Expanded payloads list
        base_payloads = []
        
        # Load custom payloads if available
        payload_path = self.config.get('wordlists.open_redirect_payloads', 'wordlists/open_redirect_payloads.txt')
        custom_payloads = self.load_list(payload_path)
        if custom_payloads:
            base_payloads.extend(custom_payloads)
            
        # Deduplicate
        payloads = list(set(base_payloads))

        # Track tested parameters to avoid duplicates
        # Set of (path, param_name)
        self.tested_params = set()

        # Test URLs with parameters
        if urls:
            for url in urls:
                self._test_url(url, payloads)

        # Test Forms
        if forms:
            for form in forms:
                self._test_form(form, payloads)

    def _test_url(self, url, payloads):
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return
        
        # Normalize path to avoid duplicates like /foo and /foo/
        path = parsed.path.rstrip('/')
        
        params = urllib.parse.parse_qs(parsed.query)
        for param in params:
            # Check if we already tested this parameter on this path
            if (path, param) in self.tested_params:
                continue
                
            self.tested_params.add((path, param))

            for payload in payloads:
                # Construct new URL with payload
                query_dict = params.copy()
                query_dict[param] = [payload]
                new_query_str = urllib.parse.urlencode(query_dict, doseq=True)
                target_url = urllib.parse.urlunparse(parsed._replace(query=new_query_str))

                if self._check_redirect(target_url, payload, f"URL Parameter: {param}"):
                    break # Stop testing this parameter if vuln found

    def _test_form(self, form, payloads):
        action = form.get('action')
        if not action:
            return
            
        # Normalize action path
        parsed_action = urllib.parse.urlparse(action)
        path = parsed_action.path.rstrip('/')

        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        for inp in inputs:
            name = inp.get('name')
            if not name:
                continue
                
            # Check if we already tested this input on this form action
            if (path, name) in self.tested_params:
                continue
            
            self.tested_params.add((path, name))

            # Skip hidden CSRF tokens or submit buttons usually
            inp_type = inp.get('type', '').lower()
            if inp_type == 'submit':
                continue

            for payload in payloads:
                data = {}
                # Fill other inputs with default or empty
                for other_inp in inputs:
                    other_name = other_inp.get('name')
                    if other_name:
                        data[other_name] = other_inp.get('value', 'test')
                
                # Set payload
                data[name] = payload
                
                try:
                    if method == 'GET':
                        response = self.session.get(action, params=data, allow_redirects=False, timeout=5)
                    else:
                        response = self.session.post(action, data=data, allow_redirects=False, timeout=5)
                        
                    if self._analyze_response(response, payload, f"Form Field: {name} at {action}"):
                        break # Stop testing this input if vuln found
                    
                except Exception:
                    pass

    def _check_redirect(self, url, payload, context):
        try:
            # Don't follow redirects automatically to check the Location header
            response = self.session.get(url, allow_redirects=False, timeout=5)
            return self._analyze_response(response, payload, context, url)
        except Exception:
            return False

    def _analyze_response(self, response, payload, context, target_url=None):
        if not response:
            return False

        # 1. Check HTTP Redirects (3xx)
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if self._is_valid_redirect(location, payload):
                self._report_vuln(target_url or response.url, location, context, "HTTP Header")
                return True

        # 2. Check Meta Refresh
        # <meta http-equiv="refresh" content="0;url=http://google.com">
        if 'refresh' in response.text.lower():
            meta_matches = re.findall(r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?[^>]*url=([^"\'>]+)["\']?', response.text, re.IGNORECASE)
            for match in meta_matches:
                if self._is_valid_redirect(match, payload):
                    self._report_vuln(target_url or response.url, match, context, "Meta Refresh")
                    return True

        # 3. Check JavaScript Redirects (Heuristic)
        # window.location = "..."
        # window.location.href = "..."
        # location.href = "..."
        # location.replace("...")
        if 'location' in response.text.lower():
            # Simple check if payload is inside a JS string assigned to location
            # This is tricky to regex perfectly, but we can check if payload appears near location assignment
            if payload in response.text:
                # Check for common patterns
                js_patterns = [
                    r'window\.location\s*=\s*["\'](.*?)["\']',
                    r'window\.location\.href\s*=\s*["\'](.*?)["\']',
                    r'location\.href\s*=\s*["\'](.*?)["\']',
                    r'location\.replace\s*\(\s*["\'](.*?)["\']'
                ]
                for pattern in js_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    for match in matches:
                        if self._is_valid_redirect(match, payload):
                            self._report_vuln(target_url or response.url, match, context, "JavaScript")
                            return True
        return False

    def _is_valid_redirect(self, location, payload):
        """
        Verifies if the location matches the payload target.
        Handles relative URLs if the payload was relative, but mostly checks if the payload's domain is in the location.
        """
        if not location:
            return False
            
        # Decode location just in case
        location = urllib.parse.unquote(location)
        
        # If payload is a full URL, check if it's in the location
        if payload in location:
            return True
            
        # Specific check for google.com which is our main test domain
        if "google.com" in payload and "google.com" in location:
            return True
            
        return False

    def _report_vuln(self, url, redirect_target, context, method):
        self.add_vulnerability(
            "Open Redirect",
            f"Open Redirect found at {url}. {context}. Redirects to: {redirect_target}",
            "Medium"
        )
        self.logger.info(f"Open Redirect found at {url} ({method}) -> {redirect_target}")
