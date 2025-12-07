import requests
from modules.base import BaseScanner
import os
import asyncio
import aiohttp

class BruteForceScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Testing brute force on login forms at {self.target_url}")

        if not forms:
            return

        users = self.load_list("wordlists/users.txt")
        passwords = self.load_list("wordlists/passwords.txt")

        # Deduplicate forms based on action
        unique_forms = {f['action']: f for f in forms if self.is_login_form(f)}.values()

        if not unique_forms:
            return

        # Run async scan
        asyncio.run(self._scan_async(unique_forms, users, passwords))

    async def _scan_async(self, forms, users, passwords):
        # Limit concurrency
        concurrency = self.config.get('brute_force.concurrency', 50)
        self.logger.info(f"Using brute force concurrency: {concurrency}")
        semaphore = asyncio.Semaphore(concurrency) 
        
        async with aiohttp.ClientSession(headers=self.session.headers) as session:
            tasks = []
            for form in forms:
                action = form.get('action')
                if not action:
                    continue
                
                combinations = [(user, pwd) for user in users for pwd in passwords]
                
                for user, pwd in combinations:
                    tasks.append(self._attempt_login_async(session, semaphore, form, action, user, pwd))
            
            # Run all tasks
            await asyncio.gather(*tasks)

    async def _attempt_login_async(self, session, semaphore, form, action, user, pwd):
        data = {}
        # Fill form data
        for inp in form['inputs']:
            name = inp.get('name')
            if not name:
                continue
            
            name_lower = name.lower()
            inp_type = inp.get('type', '').lower() if inp.get('type') else ''
            
            if inp_type == 'password' or 'pass' in name_lower:
                data[name] = pwd
            elif 'user' in name_lower or 'email' in name_lower or 'login' in name_lower or 'uname' in name_lower:
                data[name] = user

        if not data:
            return

        async with semaphore:
            try:
                async with session.post(action, data=data, timeout=10, allow_redirects=True, ssl=False) as response:
                    # Read response content to check for success
                    text = await response.text()
                    history = response.history
                    
                    if self._is_successful_login_async(response, text, history):
                        self.add_vulnerability(
                            "Weak Credentials",
                            f"Login successful with {user}:{pwd} on {action}",
                            "High"
                        )
                        # Optional: Cancel other tasks if one succeeds, but for now we let them finish
            except Exception as e:
                # self.logger.error(f"Async request error: {e}")
                pass

    def _is_successful_login_async(self, response, text, history):
        # Logic similar to is_successful_login but using async response data
        
        # Simple check: no redirect to login or error message
        if not response.url:
            return False
            
        # Common error messages found in login pages
        error_keywords = [
            "invalid password", "incorrect password", "wrong password",
            "invalid username", "incorrect username", "wrong username",
            "login failed", "failed login", "access denied",
            "try again", "bad credentials", "user not found"
        ]
        
        response_text = text.lower()
        for keyword in error_keywords:
            if keyword in response_text:
                return False
                
        # Check if we are still on the login page (if identifiable)
        if 'login' in str(response.url).lower():
            return False
            
        # Check if we were redirected to a login page
        if history:
            for history_resp in history:
                if 'login' in history_resp.headers.get('Location', '').lower():
                    return False

        # Check if the response contains a password field (indicating we are still on a login form)
        if 'type="password"' in response_text or "type='password'" in response_text:
            return False
            
        # Stricter check for 200 OK pages that might be "empty" or just a template
        if not history:
             success_keywords = ["logout", "sign out", "log out", "welcome", "dashboard", "profile", "account"]
             if not any(k in response_text for k in success_keywords):
                 return False

        return response.status == 200

    def is_login_form(self, form):
        action = form.get('action', '').lower()
        
        # Exclude registration/signup pages
        registration_keywords = ['register', 'signup', 'newuser', 'create', 'join']
        if any(keyword in action for keyword in registration_keywords):
            return False

        inputs = form.get('inputs', [])
        
        # Heuristic: Login forms usually have few inputs (user, pass, maybe remember me, csrf)
        # Registration forms have many (confirm pass, email, name, etc.)
        if len(inputs) > 4:
            return False

        has_password = False
        has_confirm = False
        
        for inp in inputs:
            name = inp.get('name', '').lower() if inp.get('name') else ''
            inp_type = inp.get('type', '').lower() if inp.get('type') else ''
            
            # Check for registration fields
            if 'confirm' in name or 'verify' in name:
                has_confirm = True
            
            # Strong indicator: type="password"
            if inp_type == 'password' or 'pass' in name:
                has_password = True
        
        # If it has a confirm password field, it's likely a registration form
        if has_confirm:
            return False
                
        return has_password
    
    def is_successful_login(self, response):
        # Kept for compatibility if needed, but async version uses _is_successful_login_async
        return False