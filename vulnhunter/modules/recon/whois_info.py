from modules .base import BaseScanner 
import requests 
from datetime import datetime 
import yaml 
import os 

class WhoisScanner (BaseScanner ):
    def __init__ (self ,target_url ,session ,config_path ="config.yaml"):
        super ().__init__ (target_url =target_url ,session =None ,config =config_path )
        self .api_key =self .load_api_key (os .path .join (os .path .dirname (__file__ ),"../../config.yaml"))


    def load_api_key (self ,config_path ):
        with open (config_path ,"r")as f :
            config =yaml .safe_load (f )
        return config .get ("env",{}).get ("apiKey")

    def _format_date (self ,ts ):
        if isinstance (ts ,list ):
            ts =ts [0 ]
        try :
            return datetime .utcfromtimestamp (int (ts )).strftime ('%Y-%m-%d %H:%M:%S')
        except :
            return str (ts )

    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Performing WHOIS lookup on {self .target_url }")
        try :
            domain =self .target_url .replace ("http://","").replace ("https://","").split ("/")[0 ]
            url =f"https://api.api-ninjas.com/v1/whois?domain={domain }"
            headers ={"X-Api-Key":self .api_key }

            response =requests .get (url ,headers =headers )
            data =response .json ()

            if registrar :=data .get ("registrar"):
                self .add_vulnerability ("Registrar Info",f"Registrar: {registrar }","Info")
            if name :=data .get ("name"):
                self .add_vulnerability ("Registrant Name",f"Name: {name }","Info")
            if org :=data .get ("org"):
                self .add_vulnerability ("Registrant Organization",f"Org: {org }","Info")
            if emails :=data .get ("emails"):
                if not isinstance (emails ,list ):
                    emails =[emails ]
                for email in emails :
                    self .add_vulnerability ("Contact Email",f"Email: {email }","Info")
            if creation :=data .get ("creation_date"):
                self .add_vulnerability ("Domain Creation Date",f"Created on: {self ._format_date (creation )}","Info")
            if expiration :=data .get ("expiration_date"):
                self .add_vulnerability ("Domain Expiration Date",f"Expires on: {self ._format_date (expiration )}","Info")
            if updated :=data .get ("updated_date"):
                self .add_vulnerability ("Last Updated",f"Updated on: {self ._format_date (updated )}","Info")
            if name_servers :=data .get ("name_servers"):
                if not isinstance (name_servers ,list ):
                    name_servers =[name_servers ]
                for ns in name_servers :
                    self .add_vulnerability ("Name Server",f"NS: {ns }","Info")

        except Exception as e :
            self .logger .error (f"Error in WHOIS scan: {e }")
