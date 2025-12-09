from modules .base import BaseScanner 
import os 
from urllib .parse import urlparse ,parse_qs ,urlencode ,urlunparse 
import html 

class XSSScanner (BaseScanner ):

    def __init__ (self ,target_url ,session ,config ):
        super ().__init__ (target_url ,session ,config )


        self .seen_form_vulns =set ()
        self .seen_url_vulns =set ()




    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Scanning for XSS on {self .target_url }")

        payloads =self .load_payloads ("wordlists/xss_payloads.txt")




        if forms :
            for form in forms :
                result =self .scan_form_for_xss (form ,payloads )

                if result :
                    field ,payload ,action =result 
                    vuln_id =f"{action }|{field }"


                    if vuln_id in self .seen_form_vulns :
                        continue 

                    self .seen_form_vulns .add (vuln_id )


                    raw_desc =f"XSS found in form! Field: {field } | Payload: {payload } | Action: {action }"


                    safe_desc =html .escape (raw_desc )

                    self .add_vulnerability ("Cross-Site Scripting (XSS)",safe_desc ,"High")




        if urls :
            for url in urls :
                result =self .scan_url_for_xss (url ,payloads )

                if result :
                    param ,payload ,test_url =result 

                    parsed =urlparse (url )
                    base_url =f"{parsed .scheme }://{parsed .netloc }{parsed .path }"

                    vuln_id =f"{base_url }|{param }"

                    if vuln_id in self .seen_url_vulns :
                        continue 

                    self .seen_url_vulns .add (vuln_id )


                    raw_desc =f"XSS found in URL! Param: {param } | Payload: {payload } | URL: {test_url }"


                    safe_desc =html .escape (raw_desc )

                    self .add_vulnerability ("Cross-Site Scripting (XSS)",safe_desc ,"High")




    def load_payloads (self ,path ):
        if os .path .exists (path ):
            with open (path ,"r")as f :
                return [p .strip ()for p in f if p .strip ()]
        return [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>"
        ]




    def detect_xss (self ,response ,payload ):
        body =response .text .lower ()


        encoded =urlencode ({"x":payload })[2 :].lower ()
        if encoded in body :
            return True 

        return False 




    def scan_form_for_xss (self ,form ,payloads ):

        action =form .get ("action")
        inputs =form .get ("inputs",[])

        base_data ={i ["name"]:"test"for i in inputs if i .get ("name")}

        for inp in inputs :
            field =inp .get ("name")
            if not field :
                continue 

            for payload in payloads :

                test_data =base_data .copy ()
                test_data [field ]=payload 

                response =self .session .post (action ,data =test_data )

                if self .detect_xss (response ,payload ):
                    return (field ,payload ,action )

        return None 




    def scan_url_for_xss (self ,url ,payloads ):

        parsed =urlparse (url )
        params =parse_qs (parsed .query )

        if not params :
            return None 

        for param in params :

            for payload in payloads :

                test_params =params .copy ()
                test_params [param ]=payload 

                test_query =urlencode (test_params ,doseq =True )

                test_url =urlunparse ((
                parsed .scheme ,parsed .netloc ,parsed .path ,
                parsed .params ,test_query ,parsed .fragment 
                ))

                response =self .session .get (test_url )

                if self .detect_xss (response ,payload ):
                    return (param ,payload ,test_url )

        return None 
