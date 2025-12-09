from modules .base import BaseScanner 
from urllib .parse import urlparse 

class CSRFScanner (BaseScanner ):
    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Testing for CSRF vulnerabilities at {self .target_url }")

        if not forms :
            return 


        csrf_token_names =[
        'csrf_token','csrftoken','csrf',
        'xsrf_token','xsrftoken','xsrf',
        'user_token','authenticity_token',
        '_token','__requestverificationtoken',
        'token','nonce'
        ]


        sensitive_keywords =[
        'password','email','update','change',
        'delete','remove','add','create',
        'setting','profile','account','admin'
        ]

        for form in forms :
            action =form .get ('action','')
            method =form .get ('method','GET').upper ()
            inputs =form .get ('inputs',[])




            if method !='POST':

                if not any (k in action .lower ()for k in sensitive_keywords ):
                    continue 


            is_sensitive =False 


            if any (k in action .lower ()for k in sensitive_keywords ):
                is_sensitive =True 


            for inp in inputs :
                name =inp .get ('name')
                if name :
                    name =name .lower ()
                    if any (k in name for k in sensitive_keywords ):
                        is_sensitive =True 
                        break 

            if not is_sensitive :
                continue 


            has_token =False 
            for inp in inputs :
                name =inp .get ('name')
                if name :
                    name =name .lower ()
                    if any (token_name in name for token_name in csrf_token_names ):
                        has_token =True 
                        break 

            if not has_token :
                self .logger .info (f"Potential CSRF found in form: {action }")
                self .add_vulnerability (
                "CSRF",
                f"Sensitive form at {action } appears to lack anti-CSRF tokens.",
                "Medium"
                )
