import re 
from modules .base import BaseScanner 

class WAFDetectScanner (BaseScanner ):


    WAF_SIGNATURES ={
    'Cloudflare':[
    ('Server',r'cloudflare'),
    ('CF-RAY',r'.*'),
    ],
    'ModSecurity':[

    ('Server',r'mod_security/?([\d\.]*)'),
    ('X-Powered-By',r'mod_security/?([\d\.]*)'),
    ],
    'Incapsula (Imperva)':[
    ('X-Iinfo',r'.*'),
    ('X-CDN',r'incapsula'),
    ],
    'Sucuri Cloudproxy':[

    ('Server',r'sucuri/cloudproxy/?(.*)'),
    ('X-Sucuri-ID',r'.*'),
    ],
    'AWS WAF (via ELB/ALB)':[
    ('Server',r'awselb'),
    ('X-Request-ID',r'.*'),
    ],
    'Akamai':[
    ('Server',r'akamai'),
    ('X-Akamai-Transformed',r'.*'),
    ],
    'F5 BIG-IP':[
    ('Set-Cookie',r'(bigip|f5traffic)'),
    ],
    'Barracuda WAF':[
    ('Set-Cookie',r'barra_counter_session'),
    ]
    }

    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Detecting WAF on {self .target_url }")


        payload ="\" or 1=1 -- <script>alert('WAF')</script>"

        try :


            res =self .session .get (self .target_url ,params ={'test':payload },allow_redirects =False )


            if res .status_code in [403 ,406 ,501 ]:
                self .add_vulnerability (
                "WAF Detected (Active Block)",
                f"WAF blocked a basic SQL/XSS payload, returned status code {res .status_code }.",
                "Info"
                )
            else :
                self .logger .success (f"Active check status: {res .status_code }. No immediate block detected.")


            detected_waf =self ._passive_check (res .headers )

            if detected_waf :
                self .add_vulnerability (
                "WAF Detected (Passive Signature)",
                f"Identified WAF(s): {detected_waf }",
                "Info"
                )
                return True 

            return False 

        except Exception as e :
            self .logger .error (f"Error detecting WAF: {e }")
            return False 

    def _passive_check (self ,headers ):
        """Checks HTTP headers against known WAF signatures using Regex."""

        detected_wafs ={}

        for waf_name ,signatures in self .WAF_SIGNATURES .items ():
            for header_name ,pattern_str in signatures :


                header_value =headers .get (header_name )

                if header_value :

                    match =re .search (pattern_str ,header_value ,re .IGNORECASE )

                    if match :
                        version_info =match .group (1 ).strip ()if len (match .groups ())>0 and match .group (1 )else ""

                        if version_info :
                            version_detail =f" ({version_info })"
                        else :
                            version_detail =" (Signature found)"


                        detected_wafs [waf_name ]=f"{waf_name }{version_detail }"
                        break 

        if detected_wafs :

            return "; ".join (detected_wafs .values ())
        return None 
