from colorama import Fore, Style
from modules.base import BaseScanner
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

class RFIScanner(BaseScanner):
    """
    Scanner to detect Remote File Inclusion (RFI) vulnerabilities 
    using a self-referencing (loopback) technique.
    """
    
    COMMON_RFI_PARAMS = ["file", "page", "id", "path"]
    
    VULN_TYPE = "Remote File Inclusion (RFI)"
    VULN_SEVERITY = "Critical" 

    def _setup_self_reference_payloads(self):
        """
        Fetches the target's own page content to create a unique signature 
        for a self-referencing RFI test.
        """
        # Fetch the target's main page to get a unique signature
        response = self.session.get(self.target_url)
        
        if not response or response.status_code != 200:
            self.logger.warning(f"Failed to fetch {self.target_url} for RFI signature.")
            return []

        # Use a stable, unique part of the HTML as the signature (e.g., 100 chars after <html>)
        # Using a snippet avoids issues with dynamic content like timestamps.
        try:
            # Find the start of the <body> or <html> tag and take a snippet
            content_start = response.text.lower().find('<html')
            if content_start == -1:
                 content_start = response.text.lower().find('<body')
            
            if content_start != -1:
                # Grab a unique 100-character snippet after the tag
                signature = response.text[content_start + 50: content_start + 150].strip()
            else:
                # Fallback to the very start if tags are missed
                signature = response.text[:100].strip()

        except Exception:
            # Final fallback if parsing fails
            signature = None
            
        if not signature:
            self.logger.error("Could not extract a suitable self-reference signature.")
            return []

        # The payload is the target URL itself
        payload_url = self.target_url
        
        return [
            ("Self-Referencing Inclusion Test", signature, payload_url),
            # Use Null Byte termination to bypass simple file extension filters (e.g., filter.php)
            ("Self-Referencing (Null Byte)", signature, payload_url + "%00"),
        ]

    def scan(self, forms=None, urls=None):
        self.logger.info(f"Starting Remote File Inclusion (RFI) scan on {self.target_url}")
        
        payloads_to_test = self._setup_self_reference_payloads()
        
        if not payloads_to_test:
            print(f"{Fore.RED}[!] RFI Scan skipped: Could not generate a self-reference signature.{Style.RESET_ALL}")
            return
            
        print(f"{Fore.YELLOW}[*] Starting Remote File Inclusion (RFI) Scan (Self-Referencing Method).{Style.RESET_ALL}")

        # 1. Test GET parameters on found URLs
        if urls:
            for url in urls:
                self._test_url_parameters(url, payloads_to_test)

        # 2. Test input fields on found forms
        if forms:
            for form in forms:
                self._test_form_inputs(form, payloads_to_test)

    # --- Re-use the existing testing methods from the LFI/RFI structure ---

    def _test_url_parameters(self, url, payloads_to_test):
        """Tests each existing and common GET parameter of the URL for RFI."""
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params_to_test = set(query_params.keys()).union(self.COMMON_RFI_PARAMS)
        
        for key in params_to_test:
            for name, expected_sig, payload in payloads_to_test:
                
                test_params = query_params.copy()
                test_params[key] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                response = self.session.get(test_url)
                self._check_response(response, name, expected_sig, f"GET parameter '{key}' at {test_url}")
                
    def _test_form_inputs(self, form, payloads_to_test):
        """Tests each form input field for RFI."""
        url = form['action']
        method = form['method']
        
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name')
            if not input_name:
                continue

            for name, expected_sig, payload in payloads_to_test:
                data = {i.get('name'): i.get('name') for i in form.get('inputs', []) if i.get('name')}
                data[input_name] = payload
                
                response = None
                if method == 'POST':
                    response = self.session.post(url, data=data)
                elif method == 'GET':
                    response = self.session.get(url, params=data)
                
                if response:
                    self._check_response(response, name, expected_sig, f"{method} form field '{input_name}' at {url}")

    def _check_response(self, response, payload_name, expected_signature, location_detail):
        """Checks for the signature and reports the vulnerability."""
        if response and expected_signature in response.text:
            details = (
                f"RFI detected! The target successfully included its own page content via the remote file inclusion vulnerability. "
                f"Location: {location_detail}"
            )
            self.add_vulnerability(
                self.VULN_TYPE,
                details,
                self.VULN_SEVERITY
            )
            print(f"{Fore.RED}[!] RFI VULNERABILITY FOUND: {payload_name} - {location_detail}{Style.RESET_ALL}")