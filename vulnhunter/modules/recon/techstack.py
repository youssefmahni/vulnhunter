from modules .base import BaseScanner 
from Wappalyzer import Wappalyzer ,WebPage 

class TechStackScanner (BaseScanner ):
    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Detecting technologies for {self .target_url }")

        try :

            wappalyzer =Wappalyzer .latest ()


            webpage =WebPage .new_from_url (self .target_url )


            tech =wappalyzer .analyze_with_versions_and_categories (webpage )
            print ("tech : ",tech )
            for name ,data in tech .items ():
                print ("name : ",name ,'data : ',data )
                versions =data ["versions"]or ["unknown"]
                version =versions [0 ]if versions else "unknown"

                categories_data =data ["categories"]or []
                categories =", ".join (cat for cat in categories_data )

                description =f"{name } | Version: {version } | Categories: {categories }"
                self .add_vulnerability ("Technology Detected",description ,"Info")


        except Exception as e :
            self .logger .error (f"Wappalyzer detection failed: {e }")
