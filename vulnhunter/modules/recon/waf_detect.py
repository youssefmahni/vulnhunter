import re
from modules.base import BaseScanner

class WAFDetectScanner(BaseScanner):
    # Dictionary mapping WAF Name to a list of (Header, Regex Pattern) tuples
    # The pattern uses a capturing group () to grab the version/details where possible.
    WAF_SIGNATURES = {
        'Cloudflare': [
            ('Server', r'cloudflare'),
            ('CF-RAY', r'.*'), # Header confirms existence, version is rare
        ],
        'ModSecurity': [
            # Captures version number (e.g., Mod_Security/2.9.2)
            ('Server', r'mod_security/?([\d\.]*)'),
            ('X-Powered-By', r'mod_security/?([\d\.]*)'),
        ],
        'Incapsula (Imperva)': [
            ('X-Iinfo', r'.*'), # Unique header confirms existence
            ('X-CDN', r'incapsula'),
        ],
        'Sucuri Cloudproxy': [
            # Captures details (e.g., Sucuri/Cloudproxy)
            ('Server', r'sucuri/cloudproxy/?(.*)'),
            ('X-Sucuri-ID', r'.*'),
        ],
        'AWS WAF (via ELB/ALB)': [
            ('Server', r'awselb'),
            ('X-Request-ID', r'.*'), # Generic AWS header check
        ],
        'Akamai': [
            ('Server', r'akamai'),
            ('X-Akamai-Transformed', r'.*'),
        ],
        'F5 BIG-IP': [
            ('Set-Cookie', r'(bigip|f5traffic)'), # Cookie existence confirms WAF type
        ],
        'Barracuda WAF': [
            ('Set-Cookie', r'barra_counter_session'),
        ]
    }

    def scan(self, forms=None, urls=None):
        print(f"[*] Detecting WAF on {self.target_url}")

        # Use a classic injection/XSS payload for the active check
        payload = "\" or 1=1 -- <script>alert('WAF')</script>"
        
        try:
            # Send the malicious payload to check for immediate blocking
            # Set allow_redirects=False to catch 302/403 block pages
            res = self.session.get(self.target_url, params={'test': payload}, allow_redirects=False)

            # 1. Active Check: Check for immediate blocking response
            if res.status_code in [403, 406, 501]:
                self.add_vulnerability(
                    "WAF Detected (Active Block)",
                    f"WAF blocked a basic SQL/XSS payload, returned status code {res.status_code}.",
                    "Info"
                )
            else:
                print(f"[+] Active check status: {res.status_code}. No immediate block detected.")

            # 2. Passive Check: Check headers for WAF signatures and versions
            detected_waf = self._passive_check(res.headers)
            
            if detected_waf:
                self.add_vulnerability(
                    "WAF Detected (Passive Signature)",
                    f"Identified WAF(s): {detected_waf}",
                    "Info"
                )
                return True
            
            return False

        except Exception as e:
            print(f"(!) Error detecting WAF: {e}")
            return False

    def _passive_check(self, headers):
        """Checks HTTP headers against known WAF signatures using Regex."""
        
        detected_wafs = {}

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for header_name, pattern_str in signatures:
                
                # The requests 'headers' object is a case-insensitive dictionary, which is an optimization.
                header_value = headers.get(header_name) 

                if header_value:
                    # Search for the pattern in the header value, ignoring case
                    match = re.search(pattern_str, header_value, re.IGNORECASE)

                    if match:
                        version_info = match.group(1).strip() if len(match.groups()) > 0 and match.group(1) else ""
                        
                        if version_info:
                            version_detail = f" ({version_info})"
                        else:
                            version_detail = " (Signature found)"

                        # Store the most detailed detection, overriding simple detections with specific ones
                        detected_wafs[waf_name] = f"{waf_name}{version_detail}"
                        break # Move to next WAF once one signature is found

        if detected_wafs:
            # Return a comma-separated string of all unique detections
            return "; ".join(detected_wafs.values())
        return None
