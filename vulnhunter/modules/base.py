from core .logger import logger 

class BaseScanner :
    def __init__ (self ,target_url ,session ,config =None ):
        self .target_url =target_url 
        self .session =session 
        self .config =config 
        self .vulnerabilities =[]
        self .logger =logger 

    def scan (self ,forms =None ,urls =None ):
        raise NotImplementedError ("Subclasses must implement scan method")

    def add_vulnerability (self ,vuln_type ,details ,severity ="Info"):
        self .vulnerabilities .append ({
        "type":vuln_type ,
        "details":details ,
        "severity":severity 
        })

    def load_list (self ,path ):
        import os 
        if os .path .exists (path ):
            with open (path ,'r')as f :
                return [line .strip ()for line in f if line .strip ()]
        return []