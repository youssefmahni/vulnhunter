from modules .base import BaseScanner 
import urllib .parse 

class CRLFScanner (BaseScanner ):
    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Testing for CRLF Injection at {self .target_url }")

        payloads =self .load_list ("wordlists/crlf_payloads.txt")
        if not payloads :
            self .logger .error ("No CRLF payloads found.")
            return 


        for url in urls :
            parsed =urllib .parse .urlparse (url )
            if not parsed .query :
                continue 

            params =urllib .parse .parse_qs (parsed .query )
            for param in params :
                for payload in payloads :

                    query_dict =params .copy ()
                    query_dict [param ]=[payload ]
                    new_query_str =urllib .parse .urlencode (query_dict ,doseq =True )
                    target_url =urllib .parse .urlunparse (parsed ._replace (query =new_query_str ))

                    try :
                        response =self .session .get (target_url ,timeout =5 )



                        for header ,value in response .headers .items ():
                            if header .lower ()=='set-cookie'and 'vulnhunter=true'in value :
                                self .add_vulnerability (
                                "CRLF Injection",
                                f"CRLF Injection found at {target_url } (Cookie set)",
                                "Medium"
                                )
                                return 

                    except Exception as e :
                        pass 
