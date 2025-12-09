import requests 
from urllib .parse import urljoin 
import urllib3 
from core .logger import logger 

urllib3 .disable_warnings (urllib3 .exceptions .InsecureRequestWarning )

class Requester :
    def __init__ (self ,timeout =10 ,user_agent ="VulnHunter/1.0"):
        self .session =requests .Session ()
        self .session .headers .update ({"User-Agent":user_agent })
        self .session .verify =False 
        self .timeout =timeout 

    def get (self ,url ,**kwargs ):
        try :
            kwargs .setdefault ('timeout',self .timeout )
            response =self .session .get (url ,**kwargs )
            return response 
        except requests .RequestException as e :
            logger .error (f"Request failed: {e }")
            return None 

    def post (self ,url ,data =None ,**kwargs ):
        try :
            kwargs .setdefault ('timeout',self .timeout )
            response =self .session .post (url ,data =data ,**kwargs )
            return response 
        except requests .RequestException :
            return None 

    def head (self ,url ,**kwargs ):
        try :
            kwargs .setdefault ('timeout',self .timeout )
            response =self .session .head (url ,**kwargs )
            return response 
        except requests .RequestException :
            return None 