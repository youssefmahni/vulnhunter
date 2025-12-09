import urllib .parse 
from modules .base import BaseScanner 
import re 

class OpenRedirectScanner (BaseScanner ):
    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Testing for Open Redirects at {self .target_url }")


        base_payloads =[]


        payload_path =self .config .get ('wordlists.open_redirect_payloads','wordlists/open_redirect_payloads.txt')
        custom_payloads =self .load_list (payload_path )
        if custom_payloads :
            base_payloads .extend (custom_payloads )


        payloads =list (set (base_payloads ))



        self .tested_params =set ()


        if urls :
            for url in urls :
                self ._test_url (url ,payloads )


        if forms :
            for form in forms :
                self ._test_form (form ,payloads )

    def _test_url (self ,url ,payloads ):
        parsed =urllib .parse .urlparse (url )
        if not parsed .query :
            return 


        path =parsed .path .rstrip ('/')

        params =urllib .parse .parse_qs (parsed .query )
        for param in params :

            if (path ,param )in self .tested_params :
                continue 

            self .tested_params .add ((path ,param ))

            for payload in payloads :

                query_dict =params .copy ()
                query_dict [param ]=[payload ]
                new_query_str =urllib .parse .urlencode (query_dict ,doseq =True )
                target_url =urllib .parse .urlunparse (parsed ._replace (query =new_query_str ))

                if self ._check_redirect (target_url ,payload ,f"URL Parameter: {param }"):
                    break 

    def _test_form (self ,form ,payloads ):
        action =form .get ('action')
        if not action :
            return 


        parsed_action =urllib .parse .urlparse (action )
        path =parsed_action .path .rstrip ('/')

        method =form .get ('method','GET').upper ()
        inputs =form .get ('inputs',[])

        for inp in inputs :
            name =inp .get ('name')
            if not name :
                continue 


            if (path ,name )in self .tested_params :
                continue 

            self .tested_params .add ((path ,name ))


            inp_type =inp .get ('type','').lower ()
            if inp_type =='submit':
                continue 

            for payload in payloads :
                data ={}

                for other_inp in inputs :
                    other_name =other_inp .get ('name')
                    if other_name :
                        data [other_name ]=other_inp .get ('value','test')


                data [name ]=payload 

                try :
                    if method =='GET':
                        response =self .session .get (action ,params =data ,allow_redirects =False ,timeout =5 )
                    else :
                        response =self .session .post (action ,data =data ,allow_redirects =False ,timeout =5 )

                    if self ._analyze_response (response ,payload ,f"Form Field: {name } at {action }"):
                        break 

                except Exception :
                    pass 

    def _check_redirect (self ,url ,payload ,context ):
        try :

            response =self .session .get (url ,allow_redirects =False ,timeout =5 )
            return self ._analyze_response (response ,payload ,context ,url )
        except Exception :
            return False 

    def _analyze_response (self ,response ,payload ,context ,target_url =None ):
        if not response :
            return False 


        if response .status_code in [301 ,302 ,303 ,307 ,308 ]:
            location =response .headers .get ('Location','')
            if self ._is_valid_redirect (location ,payload ):
                self ._report_vuln (target_url or response .url ,location ,context ,"HTTP Header")
                return True 



        if 'refresh'in response .text .lower ():
            meta_matches =re .findall (r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?[^>]*url=([^"\'>]+)["\']?',response .text ,re .IGNORECASE )
            for match in meta_matches :
                if self ._is_valid_redirect (match ,payload ):
                    self ._report_vuln (target_url or response .url ,match ,context ,"Meta Refresh")
                    return True 






        if 'location'in response .text .lower ():


            if payload in response .text :

                js_patterns =[
                r'window\.location\s*=\s*["\'](.*?)["\']',
                r'window\.location\.href\s*=\s*["\'](.*?)["\']',
                r'location\.href\s*=\s*["\'](.*?)["\']',
                r'location\.replace\s*\(\s*["\'](.*?)["\']'
                ]
                for pattern in js_patterns :
                    matches =re .findall (pattern ,response .text ,re .IGNORECASE )
                    for match in matches :
                        if self ._is_valid_redirect (match ,payload ):
                            self ._report_vuln (target_url or response .url ,match ,context ,"JavaScript")
                            return True 
        return False 

    def _is_valid_redirect (self ,location ,payload ):
        """
        Verifies if the location matches the payload target.
        Handles relative URLs if the payload was relative, but mostly checks if the payload's domain is in the location.
        """
        if not location :
            return False 


        location =urllib .parse .unquote (location )


        if payload in location :
            return True 


        if "google.com"in payload and "google.com"in location :
            return True 

        return False 

    def _report_vuln (self ,url ,redirect_target ,context ,method ):
        self .add_vulnerability (
        "Open Redirect",
        f"Open Redirect found at {url }. {context }. Redirects to: {redirect_target }",
        "Medium"
        )
        self .logger .info (f"Open Redirect found at {url } ({method }) -> {redirect_target }")
