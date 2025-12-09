import threading 
from colorama import Fore ,Style 

class Logger :
    _instance =None 
    _lock =threading .Lock ()

    def __new__ (cls ):
        if cls ._instance is None :
            with cls ._lock :
                if cls ._instance is None :
                    cls ._instance =super (Logger ,cls ).__new__ (cls )
        return cls ._instance 

    def log (self ,message ,end ='\n'):
        with self ._lock :
            print (message ,end =end )

    def info (self ,message ):
        self .log (f"{Fore .BLUE }[*] {message }{Style .RESET_ALL }")

    def success (self ,message ):
        self .log (f"{Fore .GREEN }[+] {message }{Style .RESET_ALL }")

    def warning (self ,message ):
        self .log (f"{Fore .YELLOW }[!] {message }{Style .RESET_ALL }")

    def error (self ,message ):
        self .log (f"{Fore .RED }[!] {message }{Style .RESET_ALL }")

    def raw (self ,message ):
        self .log (message )


logger =Logger ()
