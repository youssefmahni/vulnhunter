from colorama import Fore, Style
from modules.base import BaseScanner
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

class NoSQLIScanner(BaseScanner):
    """
    Scanner to detect NoSQL Injection (NoSQLi) vulnerabilities.
    It first attempts to fingerprint a MongoDB database using error-based probing.
    """
    
    COMMON_NOSQLI_PARAMS = ["username", "user", "email", "id", "password"]
    
    # Common NoSQL payloads for testing (MongoDB style)
    NOSQLI_PAYLOADS = [
        ("Auth Bypass ($ne)", '{"$ne": null}', "This is typically used in password/ID fields"),
        ("Auth Bypass ($gt)", '{"$gt": ""}', "This is typically used in password/ID fields"),
    ]
    
    # Signatures for MongoDB error messages used for fingerprinting
    # These often appear in the response when an invalid query syntax is injected.
    MONGODB_ERROR_SIGNATURES = [
        "bson",
        "nested",
        "bad key",
        "invalid argument",
        "improper op",
        "error near" # Generic indicator of unexpected syntax processing
    ]

    VULN_TYPE = "NoSQL Injection (Auth Bypass)"
    VULN_SEVERITY = "Critical"
    AUTH_SUCCESS_SIG = "Welcome, admin" 
    AUTH_SUCCESS_STATUS = [302, 301] 
    
    # State variable to store the detection result across methods
    NOSQL_DETECTED = False

    def _check_for_nosql_db(self):
        """
        Attempts to detect a NoSQL database (specifically MongoDB) 
        by injecting a simple syntax error and checking the response.
        """
        self.logger.info("Attempting to detect NoSQL database...")
        
        # Test Payload: Inject a simple, unexpected operator (or syntax) into a common parameter.
        # We test the main URL with a common parameter and a MongoDB-like injection.
        test_param = self.COMMON_NOSQLI_PARAMS[0] # 'username'
        test_payload = '{"$badop": 1}' # An invalid MongoDB operator
        
        test_url = self.target_url + ('?' if '?' not in self.target_url else '&') + f"{test_param}={test_payload}"
        
        try:
            response = self.session.get(test_url)
            
            if response and response.status_code == 200:
                response_text = response.text.lower()
                
                for signature in self.MONGODB_ERROR_SIGNATURES:
                    if signature in response_text:
                        self.NOSQL_DETECTED = True
                        self.add_vulnerability(
                            "Database Fingerprinting",
                            f"Likely MongoDB backend detected (Error signature: '{signature}' found in response)",
                            "Info"
                        )
                        return True
            
        except Exception as e:
            self.logger.error(f"Error during NoSQL detection probe: {e}")
            
        return False

    def scan(self, forms=None, urls=None):
        self.logger.info(f"Starting NoSQL Injection (NoSQLi) scan on {self.target_url}")
        
        # 1. Database Fingerprinting Check
        if not self._check_for_nosql_db():
            print(f"{Fore.BLUE}[*] No obvious NoSQL database detected. Skipping full NoSQLi scan.{Style.RESET_ALL}")
            return
            
        print(f"{Fore.YELLOW}[*] NoSQL database detected. Starting full NoSQL Injection scan.{Style.RESET_ALL}")
        
        # 2. Proceed with the full vulnerability scan only if NoSQL is detected
        if urls:
            for url in urls:
                self._test_url_parameters(url)

        if forms:
            for form in forms:
                self._test_form_inputs(form)

    # --- Testing methods remain the same ---

    def _test_url_parameters(self, url):
        """Tests existing and common GET parameters with NoSQL payloads."""
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params_to_test = set(query_params.keys()).union(self.COMMON_NOSQLI_PARAMS)
        
        for key in params_to_test:
            for name, payload, desc in self.NOSQLI_PAYLOADS:
                
                test_params = query_params.copy()
                test_params[key] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                response = self.session.get(test_url, allow_redirects=False)
                self._check_response(response, name, desc, f"GET parameter '{key}' at {test_url}")
                
    def _test_form_inputs(self, form):
        """Tests each form input field for NoSQLi."""
        url = form['action']
        method = form['method']
        
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name')
            # Only test common login/data fields
            if not input_name or input_name not in self.COMMON_NOSQLI_PARAMS:
                continue

            for name, payload, desc in self.NOSQLI_PAYLOADS:
                # Use a known username like 'admin' when injecting into the password field
                data = {i.get('name'): 'admin' if i.get('name') == 'username' else i.get('name') for i in form.get('inputs', []) if i.get('name')}
                
                # Inject the NoSQLi payload into the target field 
                data[input_name] = payload
                
                response = None
                if method == 'POST':
                    response = self.session.post(url, data=data, allow_redirects=False)
                elif method == 'GET':
                    response = self.session.get(url, params=data, allow_redirects=False)
                
                if response:
                    location = f"{method} form field '{input_name}' at {url}"
                    self._check_response(response, name, desc, location)

    def _check_response(self, response, payload_name, payload_description, location_detail):
        """Checks for the successful authentication signature/status."""
        
        is_vulnerable = False
        if response and (self.AUTH_SUCCESS_SIG in response.text or response.status_code in self.AUTH_SUCCESS_STATUS):
            is_vulnerable = True

        if is_vulnerable:
            details = (
                f"NoSQL Injection (Auth Bypass) detected! Payload '{payload_name}' resulted in an unexpected success state "
                f"(Status: {response.status_code}). Payload description: {payload_description}. Location: {location_detail}"
            )

            self.add_vulnerability(
                self.VULN_TYPE,
                details,
                self.VULN_SEVERITY
            )
            print(f"{Fore.RED}[!] NoSQLI VULNERABILITY FOUND: {payload_name} - {location_detail}{Style.RESET_ALL}")