from modules .base import BaseScanner 
import os 
from urllib .parse import urlparse ,parse_qs ,urlencode ,urlunparse 

class SQLIScanner (BaseScanner ):

    def __init__ (self ,target_url ,session ,config ):
        super ().__init__ (target_url ,session ,config )


        self .seen_form_vulns =set ()
        self .seen_url_vulns =set ()

    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Scanning SQL Injection on {self .target_url }")

        payloads =self .load_payloads ("wordlists/sqli_payloads.txt")




        if forms :

            for form in forms :
                result =self .scan_form_for_sqli (form ,payloads )
                break 
                if result :
                    field ,payload ,action =result 
                    vuln_id =f"{action }|{field }"


                    if vuln_id in self .seen_form_vulns :
                        continue 

                    self .seen_form_vulns .add (vuln_id )

                    desc =(
                    f"Form SQLi found! Field: {field } | Payload: {payload } | Action: {action }"
                    )
                    self .add_vulnerability ("SQL Injection",desc ,"High")




        if urls :
            for url in urls :
                result =self .scan_url_for_sqli (url ,payloads )

                if result :
                    param ,payload ,test_url =result 


                    parsed =urlparse (url )
                    base_url =f"{parsed .scheme }://{parsed .netloc }{parsed .path }"
                    vuln_id =f"{base_url }|{param }"

                    if vuln_id in self .seen_url_vulns :
                        continue 

                    self .seen_url_vulns .add (vuln_id )

                    desc =(
                    f"URL SQLi found! Param: {param } | Payload: {payload } | URL: {test_url }"
                    )
                    self .add_vulnerability ("SQL Injection",desc ,"High")




    def load_payloads (self ,path ):
        if os .path .exists (path ):
            with open (path ,"r")as f :
                return [line .strip ()for line in f if line .strip ()]
        return ["' OR '1'='1","1' OR 1=1 --"]




    def detect_sqli (self ,response ):
        errors =[
        "sql syntax","mysql_fetch","mysql_num",
        "odbc","ora-","syntax error",'check the manual that corresponds to your MySQL server version for the right syntax'
        "unclosed quotation mark","sqlite",
        ]
        body =response .text .lower ()

        return any (err in body for err in errors )




    def scan_form_for_sqli (self ,form ,payloads ):

        action =form .get ("action")
        method =form .get ("method","get").lower ()
        inputs =form .get ("inputs",[])
        print ("inputs :",inputs )


        base_data ={inp ["name"]:"test"for inp in inputs 
        if inp ["type"].lower ()!="submit"}
        print ("base_data :",base_data )

        for inp in inputs :
            field =inp ["name"]
            if not field :
                continue 

            for payload in payloads :
                test_data =base_data .copy ()
                test_data [field ]=payload 

                print ("test_data :",test_data )




                if method =="post":
                    response =self .session .post (
                    action ,
                    data =test_data ,
                    cookies ={
                    "PHPSESSID":"5b2e7747f78d90e5ee50a6ca4df7ad1d",
                    "security":"low",
                    },
                    headers ={
                    "User-Agent":"Mozilla/5.0"
                    }
                    )

                else :
                    response =self .session .get (
                    action ,
                    params =test_data ,
                    cookies ={
                    "PHPSESSID":"5b2e7747f78d90e5ee50a6ca4df7ad1d",
                    "security":"low",
                    },
                    headers ={
                    "User-Agent":"Mozilla/5.0"
                    }
                    )




                if self .detect_sqli (response ):
                    return (field ,payload ,action )

                break 

        return None 




    def scan_url_for_sqli (self ,url ,payloads ):

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

                if self .detect_sqli (response ):
                    return (param ,payload ,test_url )

        return None 
