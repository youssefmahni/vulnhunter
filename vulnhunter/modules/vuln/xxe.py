from modules .base import BaseScanner 
import requests 

class XXEScanner (BaseScanner ):
    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Testing for XXE vulnerabilities at {self .target_url }")

        payloads =self .load_list ("wordlists/xxe_payloads.txt")
        if not payloads :
            self .logger .error ("No XXE payloads found.")
            return 


        for form in forms :
            action =form .get ('action')
            if not action :
                continue 


            for inp in form .get ('inputs',[]):
                name =inp .get ('name')
                if not name :
                    continue 

                for payload in payloads :
                    data ={}

                    for other_inp in form .get ('inputs',[]):
                        other_name =other_inp .get ('name')
                        if other_name :
                            data [other_name ]="test"


                    data [name ]=payload 

                    try :



                        response =self .session .post (action ,data =data ,timeout =5 )


                        if "root:x:0:0"in response .text or "[boot loader]"in response .text :
                            self .add_vulnerability (
                            "XXE Injection",
                            f"XXE vulnerability found at {action } in parameter '{name }'",
                            "High"
                            )
                            return 

                    except Exception as e :

                        pass 
