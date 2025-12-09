from modules .base import BaseScanner 
import ssl 
import socket 
from urllib .parse import urlparse 
from datetime import datetime 

class SSLCheckScanner (BaseScanner ):
    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Checking SSL/TLS on {self .target_url }")

        parsed =urlparse (self .target_url )
        domain =parsed .hostname 
        port =parsed .port or 443 

        if not domain :
            self .logger .error ("Invalid domain for SSL check")
            return 

        context =ssl .create_default_context ()
        context .check_hostname =True 
        context .verify_mode =ssl .CERT_REQUIRED 

        try :

            with socket .create_connection ((domain ,port ),timeout =10 )as sock :
                with context .wrap_socket (sock ,server_hostname =domain )as ssock :
                    self ._analyze_connection (ssock )
        except (ssl .SSLCertVerificationError ,ssl .SSLError ,socket .error )as e :
            self .logger .warning (f"Secure connection failed: {e }")
            self .logger .info ("Retrying with verification disabled to extract certificate info...")

            self .add_vulnerability (
            "SSL/TLS Connection Issue",
            f"Could not establish secure connection: {e }",
            "Low"
            )


            try :
                context =ssl .create_default_context ()
                context .check_hostname =False 
                context .verify_mode =ssl .CERT_NONE 

                with socket .create_connection ((domain ,port ),timeout =10 )as sock :
                    with context .wrap_socket (sock ,server_hostname =domain )as ssock :
                        self ._analyze_connection (ssock ,verified =False )
            except Exception as e2 :
                self .logger .error (f"Failed to connect even without verification: {e2 }")

    def _analyze_connection (self ,ssock ,verified =True ):
        cert =ssock .getpeercert (binary_form =not verified )

        cipher =ssock .cipher ()
        version =ssock .version ()

        self .logger .success (f"SSL Version: {version }")
        self .logger .success (f"Cipher: {cipher [0 ]}")

        if version in ['TLSv1','TLSv1.1']:
            self .add_vulnerability (
            "Weak TLS Version",
            f"Server supports {version }",
            "Medium"
            )

        if not verified :
             self .add_vulnerability (
             "Self-Signed or Invalid Certificate",
             "Certificate validation failed (possibly self-signed or name mismatch)",
             "Medium"
             )


        if verified :
            cert =ssock .getpeercert ()
            self ._check_cert_details (cert )

    def _check_cert_details (self ,cert ):

        subject =dict (x [0 ]for x in cert ['subject'])
        common_name =subject .get ('commonName')
        self .logger .success (f"Subject: {common_name }")


        issuer =dict (x [0 ]for x in cert ['issuer'])
        issuer_name =issuer .get ('commonName')or issuer .get ('organizationName')
        self .logger .success (f"Issuer: {issuer_name }")


        not_after_str =cert ['notAfter']

        try :
            not_after =datetime .strptime (not_after_str ,"%b %d %H:%M:%S %Y %Z")
            if datetime .utcnow ()>not_after :
                 self .add_vulnerability (
                 "Expired Certificate",
                 f"Certificate expired on {not_after_str }",
                 "High"
                 )
            else :
                days_left =(not_after -datetime .utcnow ()).days 
                self .logger .success (f"Certificate expires in {days_left } days")
                if days_left <30 :
                    self .add_vulnerability (
                    "Certificate Expiring Soon",
                    f"Certificate expires in {days_left } days",
                    "Low"
                    )
        except Exception :
            pass 