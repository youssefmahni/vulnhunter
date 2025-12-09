import yaml 
import os 

class ConfigManager :
    _instance =None 
    _config =None 

    def __new__ (cls ):
        if cls ._instance is None :
            cls ._instance =super (ConfigManager ,cls ).__new__ (cls )
            cls ._instance .load_config ()
        return cls ._instance 

    def load_config (self ,config_path =None ):
        if config_path is None :
            config_path =os .path .join (os .path .dirname (__file__ ),'..','config.yaml')
        if not os .path .exists (config_path ):
            raise FileNotFoundError (f"Configuration file not found: {config_path }")

        with open (config_path ,'r')as f :
            self ._config =yaml .safe_load (f )

    def get (self ,key ,default =None ):
        keys =key .split ('.')
        value =self ._config 
        for k in keys :
            if isinstance (value ,dict ):
                value =value .get (k )
            else :
                return default 
        return value if value is not None else default 