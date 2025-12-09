from modules .base import BaseScanner 

class BasicInfoScanner (BaseScanner ):
    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Gathering basic information on {self .target_url }")

        try :
            response =self .session .get (self .target_url )
            headers =response .headers 


            if 'Server'in headers :
                self .add_vulnerability (
                "Server Info",
                f"Server: {headers ['Server']}",
                "Info"
                )


            tech_stack =[]
            if 'X-Powered-By'in headers :
                tech_stack .append (f"X-Powered-By: {headers ['X-Powered-By']}")
            if 'X-AspNet-Version'in headers :
                tech_stack .append (f"ASP.NET: {headers ['X-AspNet-Version']}")


            if 'wp-content'in response .text :
                tech_stack .append ("WordPress")
            if 'drupal'in response .text .lower ():
                tech_stack .append ("Drupal")
            if 'jquery'in response .text .lower ():
                tech_stack .append ("jQuery")

            for tech in tech_stack :
                self .add_vulnerability (
                "Technology Detected",
                tech ,
                "Info"
                )


            if 'windows'in str (headers ).lower ():
                self .add_vulnerability ("OS Detected","Windows","Info")
            elif 'linux'in str (headers ).lower ():
                self .add_vulnerability ("OS Detected","Linux","Info")

        except Exception as e :
            self .logger .error (f"Error in basic info scan: {e }")