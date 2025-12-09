from colorama import Fore ,Style 
from modules .base import BaseScanner 
from urllib .parse import urlparse ,parse_qs ,urlunparse ,urlencode 

class NoSQLIScanner (BaseScanner ):

    COMMON_NOSQLI_PARAMS =["username","user","email","id","password","search"]


    FINGERPRINT_PAYLOAD ='{"$badop": 1}'
    FINGERPRINT_PARAM ='username'


    NOSQLI_PAYLOADS =[
    ("Error Breakout 1",'", $ne: 1 }',"Breaks string escaping and injects MongoDB operator."),
    ("Error Breakout 2",'{ "$error_test": 1 }',"Injects an invalid operator to force a known error."),
    ("Error Breakout 3 (Incomplete JSON)",'{ $ne: 1 ',"Injects incomplete JSON/BSON syntax to force a parsing error."),
    ("Error Breakout 4 (Regex Structure)",'{ "$regex": "\\", "options": "i" }',"Attempts to break string context by starting a regex structure."),
    ("Error Breakout 5 (Array Context)",'[ { "$bad_op": 1 } ]',"Tests if the input is processed in an array context, forcing a bad operator error."),

    ]


    ERROR_SIGNATURES =[
    "bson",
    "nested",
    "bad key",
    "invalid argument",
    "improper op",
    "error near",
    "invalid operator"
    ]


    VULN_TYPE ="NoSQL Injection (Auth Bypass)"
    VULN_SEVERITY ="High"
    AUTH_SUCCESS_SIG ="Welcome, admin"
    AUTH_SUCCESS_STATUS =[302 ,301 ]




    def _check_for_nosql_db (self ):
        """
        Phase 1: Attempts to detect a NoSQL database by injecting a syntax error 
        and checking for leaked database error signatures.
        """
        self .logger .info ("Phase 1: Attempting to detect NoSQL database...")


        test_url =self .target_url +('?'if '?'not in self .target_url else '&')+f"{self .FINGERPRINT_PARAM }={self .FINGERPRINT_PAYLOAD }"

        try :
            response =self .session .get (test_url )


            if response and response .status_code in [200 ,500 ,400 ]:
                response_text =response .text .lower ()


                for signature in self .ERROR_SIGNATURES :
                    if signature in response_text :
                        self .NOSQL_DETECTED =True 
                        self .add_vulnerability (
                        "Database Fingerprinting",
                        f"Likely NoSQL/MongoDB backend detected (Error signature: '{signature }' found).",
                        "Info"
                        )
                        return True 

        except Exception as e :
            self .logger .error (f"Error during NoSQL detection probe: {e }")

        return False 

    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Starting NoSQL Injection (NoSQLi) scan on {self .target_url }")


        if not self ._check_for_nosql_db ():
            print (f"{Fore .BLUE }[*] No obvious NoSQL database detected. Stopping NoSQLi scan.{Style .RESET_ALL }")
            return 

        print (f"{Fore .YELLOW }[*] NoSQL database detected. Starting full error-based injection scan...{Style .RESET_ALL }")


        if urls :
            for url in urls :
                self ._test_url_parameters (url )

        if forms :
            for form in forms :
                self ._test_form_inputs (form )

    def _test_url_parameters (self ,url ):
        """Tests existing and common GET parameters with NoSQL error payloads."""

        parsed_url =urlparse (url )
        query_params =parse_qs (parsed_url .query )


        params_to_test =set (query_params .keys ()).union (self .COMMON_NOSQLI_PARAMS )

        for key in params_to_test :
            for name ,payload ,desc in self .NOSQLI_PAYLOADS :

                test_params =query_params .copy ()
                test_params [key ]=[payload ]

                new_query =urlencode (test_params ,doseq =True )
                test_url =urlunparse (parsed_url ._replace (query =new_query ))

                response =self .session .get (test_url ,allow_redirects =False )
                self ._check_response (response ,name ,desc ,f"GET parameter '{key }' at {test_url }")

    def _test_form_inputs (self ,form ):
        """Tests each form input field for NoSQLi."""
        url =form ['action']
        method =form ['method']

        for input_field in form .get ('inputs',[]):
            input_name =input_field .get ('name')
            if not input_name or input_name not in self .COMMON_NOSQLI_PARAMS :
                continue 

            for name ,payload ,desc in self .NOSQLI_PAYLOADS :
                data ={i .get ('name'):'admin'if i .get ('name')=='username'else i .get ('name')for i in form .get ('inputs',[])if i .get ('name')}

                data [input_name ]=payload 

                response =None 
                if method =='POST':
                    response =self .session .post (url ,data =data ,allow_redirects =False )
                elif method =='GET':
                    response =self .session .get (url ,params =data ,allow_redirects =False )

                if response :
                    location =f"{method } form field '{input_name }' at {url }"
                    self ._check_response (response ,name ,desc ,location )

    def _check_response (self ,response ,payload_name ,payload_description ,location_detail ):
        """
        Confirms vulnerability by checking for leaked database error signatures 
        (error-based confirmation).
        """

        is_vulnerable =False 


        if response and response .status_code in [200 ,500 ,400 ]:
            response_text =response .text .lower ()


            for signature in self .ERROR_SIGNATURES :
                if signature in response_text :
                    is_vulnerable =True 

                    break 

        if is_vulnerable :
            details =(
            f"NoSQL Injection (Error Leakage) detected! Payload '{payload_name }' triggered a database error message "
            f"(Status: {response .status_code }). This confirms the input is processed as a database query. Location: {location_detail }"
            )

            self .add_vulnerability (
            self .VULN_TYPE ,
            details ,
            self .VULN_SEVERITY 
            )
            print (f"{Fore .RED }[!] NoSQLI VULNERABILITY FOUND (Error-Based): {payload_name } - {location_detail }{Style .RESET_ALL }")
