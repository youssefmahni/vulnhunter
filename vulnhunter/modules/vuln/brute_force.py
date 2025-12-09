import requests 
from modules .base import BaseScanner 
import os 
import asyncio 
import aiohttp 

class BruteForceScanner (BaseScanner ):
    def scan (self ,forms =None ,urls =None ):
        self .logger .info (f"Testing brute force on login forms at {self .target_url }")

        if not forms :
            return 

        users =self .load_list ("wordlists/users.txt")
        passwords =self .load_list ("wordlists/passwords.txt")


        unique_forms ={f ['action'].rstrip ('/'):f for f in forms if self .is_login_form (f )}.values ()

        if not unique_forms :
            return 


        asyncio .run (self ._scan_async (unique_forms ,users ,passwords ))

    async def _scan_async (self ,forms ,users ,passwords ):

        concurrency =self .config .get ('brute_force.concurrency',50 )
        self .logger .info (f"Using brute force concurrency: {concurrency }")
        semaphore =asyncio .Semaphore (concurrency )


        cookies =self .session .cookies .get_dict ()

        async with aiohttp .ClientSession (headers =self .session .headers ,cookies =cookies )as session :
            tasks =[]
            for form in forms :
                action =form .get ('action')
                if not action :
                    continue 

                combinations =[(user ,pwd )for user in users for pwd in passwords ]

                for user ,pwd in combinations :
                    tasks .append (self ._attempt_login_async (session ,semaphore ,form ,action ,user ,pwd ))


            await asyncio .gather (*tasks )

    async def _attempt_login_async (self ,session ,semaphore ,form ,action ,user ,pwd ):
        data ={}

        for inp in form ['inputs']:
            name =inp .get ('name')
            if not name :
                continue 

            name_lower =name .lower ()
            inp_type =inp .get ('type','').lower ()if inp .get ('type')else ''

            if inp_type =='password'or 'pass'in name_lower :
                data [name ]=pwd 
            elif ('user'in name_lower or 'email'in name_lower or 'login'in name_lower or 'uname'in name_lower )and inp_type !='submit'and inp_type !='hidden':
                data [name ]=user 
            else :


                data [name ]=inp .get ('value','')

        if not data :
            return 

        method =form .get ('method','POST').upper ()

        async with semaphore :
            try :

                if method =='GET':
                    async with session .get (action ,params =data ,timeout =10 ,allow_redirects =True ,ssl =False )as response :

                        text =await response .text ()
                        history =response .history 

                        if user =='admin'and pwd =='password':
                            pass 

                        if self ._is_successful_login_async (response ,text ,history ):
                            self .logger .info (f"SUCCESS: {user }:{pwd } on {action }")
                            self .add_vulnerability (
                            "Weak Credentials",
                            f"Login successful with {user }:{pwd } on {action }",
                            "High"
                            )
                        else :
                            pass 

                else :
                    async with session .post (action ,data =data ,timeout =10 ,allow_redirects =True ,ssl =False )as response :

                        text =await response .text ()
                        history =response .history 

                        if self ._is_successful_login_async (response ,text ,history ):
                            self .logger .info (f"SUCCESS: {user }:{pwd } on {action }")
                            self .add_vulnerability (
                            "Weak Credentials",
                            f"Login successful with {user }:{pwd } on {action }",
                            "High"
                            )
                        else :
                            pass 

            except Exception as e :
                self .logger .error (f"Async request error: {e }")
                pass 

    def _is_successful_login_async (self ,response ,text ,history ):



        if not response .url :
            return False 


        error_keywords =[
        "invalid password","incorrect password","wrong password",
        "invalid username","incorrect username","wrong username",
        "login failed","failed login","access denied",
        "try again","bad credentials","user not found",
        "username and/or password incorrect"
        ]

        response_text =text .lower ()
        for keyword in error_keywords :
            if keyword in response_text :
                return False 


        if "admin"in str (response .url )or "test"in str (response .url )or ("admin"in text and "test"in text ):
             pass 



        from urllib .parse import urlparse 

        resp_url_parsed =urlparse (str (response .url ))
        if 'login'in resp_url_parsed .path .lower ():

            return False 


        if history :
            for history_resp in history :
                loc =history_resp .headers .get ('Location','')
                loc_parsed =urlparse (loc )
                if 'login'in loc_parsed .path .lower ():

                    return False 


        success_keywords =["logout","sign out","log out","welcome","dashboard","profile","account"]
        if any (k in response_text for k in success_keywords ):
            return True 



        if 'type="password"'in response_text or "type='password'"in response_text :
            return False 


        if not history :
             success_keywords =["logout","sign out","log out","welcome","dashboard","profile","account"]
             if not any (k in response_text for k in success_keywords ):
                 return False 

        return response .status ==200 

    def is_login_form (self ,form ):
        action =form .get ('action','').lower ()


        registration_keywords =['register','signup','newuser','create','join']
        if any (keyword in action for keyword in registration_keywords ):
            return False 

        inputs =form .get ('inputs',[])



        if len (inputs )>4 :
            return False 

        has_password =False 
        has_confirm =False 

        for inp in inputs :
            name =inp .get ('name','').lower ()if inp .get ('name')else ''
            inp_type =inp .get ('type','').lower ()if inp .get ('type')else ''


            if 'confirm'in name or 'verify'in name :
                has_confirm =True 


            if inp_type =='password'or 'pass'in name :
                has_password =True 


        if has_confirm :
            return False 


        for inp in inputs :
            name =inp .get ('name')
            value =inp .get ('value')

            name_lower =name .lower ()if name else ''
            value_lower =value .lower ()if value else ''

            if 'change'in name_lower or 'change'in value_lower or 'new'in name_lower :
                return False 

        return has_password 

    def is_successful_login (self ,response ):

        return False 