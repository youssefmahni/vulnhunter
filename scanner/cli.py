import click
import concurrent.futures
from scanner.core.config import ConfigManager
from scanner.core.requester import Requester
from scanner.core.crawler import Crawler
from scanner.utils.banner import print_banner
from scanner.utils.reporter import Reporter
from scanner.modules.recon.subdomain import SubdomainScanner
from scanner.modules.recon.tech_stack import TechStackScanner
from scanner.modules.recon.directory_brute import DirectoryBruteScanner
from scanner.modules.recon.spider import SpiderScanner
from scanner.modules.recon.dorking import DorkingScanner
from scanner.modules.recon.waf import WAFScanner
from scanner.modules.config.ssl_tls import SSLScanner
from scanner.modules.config.cloud_storage import CloudStorageScanner
from scanner.modules.config.subdomain_takeover import SubdomainTakeoverScanner
from scanner.modules.config.headers import HeaderScanner
from scanner.modules.config.cors import CORSScanner
from scanner.modules.iam.auth import AuthScanner
from scanner.modules.iam.session import SessionScanner
from scanner.modules.iam.authorization import AuthZScanner
from scanner.modules.injection.sqli import SQLInjectionScanner
from scanner.modules.injection.xss import XSSScanner
from scanner.modules.injection.ssrf import SSRFScanner
from scanner.modules.injection.xxe import XXEScanner
from scanner.modules.injection.command_injection import CommandInjectionScanner
from colorama import init, Fore, Style

init(autoreset=True)

@click.command()
@click.argument('target_url', required=False)
@click.option('--phase', help='Phase to run: recon, config, iam, input')
def main(target_url, phase):
    """
    AllSafe - Web App Security Scanner
    """
    # Load configuration
    try:
        config = ConfigManager()
        print(f"{Fore.BLUE}[*] Configuration loaded successfully.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error loading configuration: {e}{Style.RESET_ALL}")
        return

    print_banner()
    
    # Use target from config if not provided
    if not target_url:
        target_url = config.get('target.url')
    
    if not target_url:
        print(f"{Fore.RED}[!] No target URL provided in args or config.{Style.RESET_ALL}")
        return

    print(f"{Fore.BLUE}[*] Starting scan on {target_url}{Style.RESET_ALL}")
    
    requester = Requester()
    
    # Verify connectivity
    response = requester.get(target_url)
    if not response:
        print(f"{Fore.RED}[!] Could not access target. Exiting.{Style.RESET_ALL}")
        return

    scanners = []
    
    # Crawl first if needed (IAM or Input phases)
    forms = []
    urls = []
    if phase in ['iam', 'input']:
        print(f"{Fore.BLUE}[*] Crawling {target_url} to discover assets...{Style.RESET_ALL}")
        crawler = Crawler(target_url, requester.session)
        crawler.crawl(depth=2)
        forms = crawler.forms
        urls = list(crawler.visited_urls)
        print(f"{Fore.BLUE}[*] Found {len(urls)} URLs and {len(forms)} forms.{Style.RESET_ALL}")

    # Phase 1: Recon
    if phase == 'recon':
        print(f"{Fore.YELLOW}[*] Running Phase 1: Reconnaissance...{Style.RESET_ALL}")
        scanners.append(SubdomainScanner(target_url, requester.session))
        scanners.append(TechStackScanner(target_url, requester.session))
        scanners.append(DirectoryBruteScanner(target_url, requester.session))
        scanners.append(SpiderScanner(target_url, requester.session))
        scanners.append(DorkingScanner(target_url, requester.session))
        scanners.append(WAFScanner(target_url, requester.session))

    # Phase 2: Config
    if phase == 'config':
        print(f"{Fore.YELLOW}[*] Running Phase 2: Configuration & Deployment Management...{Style.RESET_ALL}")
        scanners.append(SSLScanner(target_url, requester.session))
        scanners.append(CloudStorageScanner(target_url, requester.session))
        scanners.append(SubdomainTakeoverScanner(target_url, requester.session))
        scanners.append(HeaderScanner(target_url, requester.session))
        scanners.append(CORSScanner(target_url, requester.session))

    # Phase 3: IAM
    if phase == 'iam':
        print(f"{Fore.YELLOW}[*] Running Phase 3: Identity & Access Management...{Style.RESET_ALL}")
        scanners.append(AuthScanner(target_url, requester.session))
        scanners.append(SessionScanner(target_url, requester.session))
        scanners.append(AuthZScanner(target_url, requester.session))

    # Phase 4: Input
    if phase == 'input':
        print(f"{Fore.YELLOW}[*] Running Phase 4: Input Validation...{Style.RESET_ALL}")
        scanners.append(SQLInjectionScanner(target_url, requester.session))
        scanners.append(XSSScanner(target_url, requester.session))
        scanners.append(SSRFScanner(target_url, requester.session))
        scanners.append(XXEScanner(target_url, requester.session))
        scanners.append(CommandInjectionScanner(target_url, requester.session))

    # Execute scanners
    max_threads = config.get('target.threads', 5)
    print(f"{Fore.BLUE}[*] Executing scanners with {max_threads} threads...{Style.RESET_ALL}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scanner.scan, forms=forms, urls=urls) for scanner in scanners]
        concurrent.futures.wait(futures)
        
    # Collect and print vulnerabilities
    all_vulns = []
    for scanner in scanners:
        all_vulns.extend(scanner.vulnerabilities)
        
    print(f"\n{Fore.GREEN}[+] Scan completed!{Style.RESET_ALL}")
    if all_vulns:
        print(f"{Fore.RED}[!] Found {len(all_vulns)} vulnerabilities:{Style.RESET_ALL}")
        for vuln in all_vulns:
            print(f" - [{vuln['severity']}] {vuln['type']}: {vuln['details']}")
    else:
        print(f"{Fore.GREEN}[+] No vulnerabilities found.{Style.RESET_ALL}")

    # Generate Reports
    reporter = Reporter(all_vulns)
    reporter.generate_json()
    reporter.generate_html()

if __name__ == '__main__':
    main()
