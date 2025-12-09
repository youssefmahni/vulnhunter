from modules .base import BaseScanner 
from urllib .parse import urlparse 

class CORSCheckScanner (BaseScanner ):


    TEST_ORIGIN ='https://evil.com'

    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Checking CORS configuration on {self .target_url }")


        self ._test_arbitrary_reflection (self .target_url )


        self ._test_credentials_support (self .target_url )


        self ._test_wildcard (self .target_url )
        self ._test_null_origin (self .target_url )
        self ._test_options_preflight (self .target_url )


    def _get_acao_header (self ,url :str ,origin :str ,method ='GET',credentials =False )->dict :
        """Helper to send a request with a custom Origin and return relevant headers."""
        headers ={'Origin':origin }

        try :

            if method =='OPTIONS':

                headers ['Access-Control-Request-Method']='GET'
                headers ['Access-Control-Request-Headers']='Authorization, Content-Type'
                response =self .session .options (url ,headers =headers ,allow_redirects =False )
            else :
                response =self .session .get (url ,headers =headers ,allow_redirects =False )

            return {
            "acao":response .headers .get ('Access-Control-Allow-Origin'),
            "credentials":response .headers .get ('Access-Control-Allow-Credentials'),
            "acrm":response .headers .get ('Access-Control-Allow-Methods'),
            "status":response .status_code 
            }
        except Exception as e :

            return {}



    def _test_arbitrary_reflection (self ,url ):
        """Tests if the server reflects a malicious origin (the most common vulnerability)."""


        result =self ._get_acao_header (url ,self .TEST_ORIGIN )
        acao =result .get ('acao')

        if acao ==self .TEST_ORIGIN :
            self .add_vulnerability (
            "CORS Misconfiguration - Arbitrary Origin Reflection",
            f"The server reflects the malicious origin '{self .TEST_ORIGIN }' in the ACAO header, allowing cross-origin requests from any domain.",
            "High"
            )
        else :
            self .logger .info (f"Arbitrary origin check passed. ACAO: {acao }")

    def _test_credentials_support (self ,url ):
        """
        Tests if the server allows both ACAO reflection AND Access-Control-Allow-Credentials: true.
        This is required for an attacker to read user data (cookies/session).
        """


        result =self ._get_acao_header (url ,self .TEST_ORIGIN )
        acao =result .get ('acao')
        credentials =result .get ('credentials')

        if acao ==self .TEST_ORIGIN and credentials and credentials .lower ()=='true':
            self .add_vulnerability (
            "CORS Misconfiguration - Credentials Allowed with Reflection",
            "The server allows arbitrary origin reflection AND sets Access-Control-Allow-Credentials to 'true'. This is critical as an attacker can read sensitive user data.",
            "Critical"
            )
        elif acao =='*'and credentials and credentials .lower ()=='true':
             self .add_vulnerability (
             "CORS Misconfiguration - Credentials Allowed with Wildcard",
             "The server uses the wildcard '*' AND sets Access-Control-Allow-Credentials to 'true'. This is a violation of CORS specification for most browsers and a high risk if the browser is lenient.",
             "High"
             )
        else :
            self .logger .info (f"Credentials check passed. ACAO: {acao }, Credentials: {credentials }")



    def _test_wildcard (self ,url ):
        """Tests if the ACAO header is set to a simple '*'."""


        target_origin =urlparse (url ).scheme +'://'+urlparse (url ).netloc 
        acao =self ._get_acao_header (url ,target_origin ).get ('acao')

        if acao =='*':
            self .add_vulnerability (
            "CORS Misconfiguration - Wildcard Origin (*)",
            "Access-Control-Allow-Origin is set to '*', allowing access from any domain (unless credentials are used).",
            "Medium"
            )

    def _test_null_origin (self ,url ):
        """Tests if the server explicitly allows the 'null' origin."""

        acao =self ._get_acao_header (url ,'null').get ('acao')

        if acao =='null':
            self .add_vulnerability (
            "CORS Misconfiguration - Null Origin Allowed",
            "The server allows the 'null' origin, which can be exploited by malicious local files.",
            "Medium"
            )

    def _test_options_preflight (self ,url ):
        """Tests the OPTIONS preflight response for overly permissive configurations."""
        self .logger .info (f"Testing OPTIONS Preflight on {url }")


        result =self ._get_acao_header (url ,self .TEST_ORIGIN ,method ='OPTIONS')

        if result .get ('status')==200 :
            acrm =result .get ('acrm','')


            if '*'in acrm or 'PUT'in acrm or 'DELETE'in acrm :
                 self .add_vulnerability (
                 "CORS Misconfiguration - Overly Permissive Methods",
                 f"The OPTIONS preflight response allows risky methods or wildcards: {acrm }",
                 "Low"
                 )

        elif result .get ('status')==403 :
             self .logger .info ("OPTIONS request blocked (403 Forbidden).")

        else :
            self .logger .info ("OPTIONS request did not return a 200/403 (Might not be supported or is filtered).")
