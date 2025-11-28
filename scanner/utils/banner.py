from colorama import Fore, Style

def print_banner():
    banner = r"""
    {Fore.CYAN}
    ___   ____  _____       ____     
   /   | / / / / ___/____ _/ __/____ 
  / /| |/ / /  \__ \/ __ `/ /_/ _ \ 
 / ___ / / /  ___/ / /_/ / __/  __/ 
/_/  |_\/_/  /____/\__,_/_/  \___/  
                                     
      AllSafe - Advanced Security Scanner
    {Style.RESET_ALL}
    """
    print(banner)
