import click
from colorama import init, Fore, Style
import concurrent.futures

from core.config import ConfigManager
from core.requester import Requester
from core.crawler import Crawler
from utils.banner import print_banner
from core.reporter import Reporter

# Recon modules
from modules.recon.basic_info import BasicInfoScanner
from modules.recon.waf_detect import WAFDetectScanner
from modules.recon.headers_check import HeadersCheckScanner
from modules.recon.ssl_check import SSLCheckScanner
from modules.recon.cors_check import CORSCheckScanner

# Vuln modules
from modules.vuln.sqli import SQLIScanner
from modules.vuln.brute_force import BruteForceScanner

init(autoreset=True)

@click.command()
@click.argument('target_url', required=True)
def main(target_url):
    """
    VulnHunter - Advanced Web Application Security Scanner
    """
    # Load configuration
    try:
        config = ConfigManager()
        print(f"{Fore.BLUE}[*] Configuration loaded successfully.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error loading configuration: {e}{Style.RESET_ALL}")
        return

    print_banner()
    
    print(f"{Fore.BLUE}[*] Starting scan on {target_url}{Style.RESET_ALL}")
    
    requester = Requester()
    
    # Verify connectivity
    response = requester.get(target_url)
    if not response:
        print(f"{Fore.RED}[!] Could not access target. Exiting.{Style.RESET_ALL}")
        return

    # Recon phase
    print(f"{Fore.YELLOW}[*] Running Reconnaissance Phase...{Style.RESET_ALL}")
    recon_scanners = [
        BasicInfoScanner(target_url, requester.session, config),
        WAFDetectScanner(target_url, requester.session, config),
        HeadersCheckScanner(target_url, requester.session, config),
        SSLCheckScanner(target_url, requester.session, config),
        CORSCheckScanner(target_url, requester.session, config)
    ]
    
    max_threads = config.get('target.threads', 5)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scanner.scan) for scanner in recon_scanners]
        concurrent.futures.wait(futures)
        
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"{Fore.RED}[!] Exception in recon scanner: {e}{Style.RESET_ALL}")
    
    # Check for WAF
    waf_detected = any(vuln['type'] == 'WAF Detected (Active)' or vuln['type'] == 'WAF Detected (Passive)' 
                      for scanner in recon_scanners for vuln in scanner.vulnerabilities)
    
    if waf_detected:
        print(f"{Fore.RED}[!] WAF Detected!{Style.RESET_ALL}")
        if not click.confirm("Continue with vulnerability testing?"):
            print(f"{Fore.BLUE}[*] Generating recon-only report...{Style.RESET_ALL}")
            all_vulns = []
            for scanner in recon_scanners:
                all_vulns.extend(scanner.vulnerabilities)
            reporter = Reporter(all_vulns)
            reporter.generate_json()
            reporter.generate_html()
            print(f"{Fore.GREEN}[+] Recon report saved.{Style.RESET_ALL}")
            return
    
    # Crawl for vuln testing
    print(f"{Fore.BLUE}[*] Crawling for forms and URLs...{Style.RESET_ALL}")
    crawler = Crawler(target_url, requester)
    crawler.crawl()
    forms = crawler.forms
    urls = list(crawler.urls)
    print(f"{Fore.BLUE}[*] Found {len(urls)} URLs and {len(forms)} forms.{Style.RESET_ALL}")
    
    # Vuln phase
    print(f"{Fore.YELLOW}[*] Running Vulnerability Testing Phase...{Style.RESET_ALL}")
    vuln_scanners = [
        SQLIScanner(target_url, requester.session, config),
        BruteForceScanner(target_url, requester.session, config)
    ]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scanner.scan, forms=forms, urls=urls) for scanner in vuln_scanners]
        concurrent.futures.wait(futures)
        
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"{Fore.RED}[!] Exception in vuln scanner: {e}{Style.RESET_ALL}")
    
    # Collect all vulnerabilities
    all_vulns = []
    for scanner in recon_scanners + vuln_scanners:
        all_vulns.extend(scanner.vulnerabilities)
        
    print(f"\n{Fore.GREEN}[+] Scan completed!{Style.RESET_ALL}")
    if all_vulns:
        print(f"{Fore.RED}[!] Found {len(all_vulns)} issues:{Style.RESET_ALL}")
        for vuln in all_vulns:
            print(f" - [{vuln['severity']}] {vuln['type']}: {vuln['details']}")
    else:
        print(f"{Fore.GREEN}[+] No issues found.{Style.RESET_ALL}")

    # Generate reports
    reporter = Reporter(all_vulns)
    reporter.generate_json()
    reporter.generate_html()

if __name__ == '__main__':
    main()