import click
import concurrent.futures

from core.config import ConfigManager
from core.requester import Requester
from core.crawler import Crawler
from utils.banner import print_banner
from core.reporter import Reporter
from core.logger import logger

# Recon modules
from modules.recon.basic_info import BasicInfoScanner
from modules.recon.waf_detect import WAFDetectScanner
from modules.recon.headers_check import HeadersCheckScanner
from modules.recon.ssl_check import SSLCheckScanner
from modules.recon.cors_check import CORSCheckScanner
from modules.recon.whois_info import WhoisScanner

from modules.recon.dns_scanner import DNSScanner

from modules.recon.dirb_scanner import DirbScanner
from modules.recon.CloudStorage import CloudStorage

# Vuln modules
from modules.vuln.sqli import SQLIScanner
from modules.vuln.brute_force import BruteForceScanner

@click.command()
@click.argument('target_url', required=True)
def main(target_url):
    """
    VulnHunter - Advanced Web Application Security Scanner
    """
    # Load configuration
    try:
        config = ConfigManager()
        logger.info("Configuration loaded successfully.")
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return

    print_banner()
    
    logger.info(f"Starting scan on {target_url}")
    
    requester = Requester()
    
    # Verify connectivity
    response = requester.get(target_url)
    if not response:
        logger.error("Could not access target. Exiting.")
        return

    # Recon phase
    logger.warning("Running Reconnaissance Phase...")
    recon_scanners = [

        BasicInfoScanner(target_url, requester.session, config),
        WAFDetectScanner(target_url, requester.session, config),
        HeadersCheckScanner(target_url, requester.session, config),
        SSLCheckScanner(target_url, requester.session, config),
        CORSCheckScanner(target_url, requester.session, config),
        DirbScanner(target_url, requester.session, config),
        WhoisScanner(target_url,requester.session,config),
        DNSScanner(target_url,requester.session,config),
        CloudStorage(target_url,requester.session,config)
        
    ]
    
    max_threads = config.get('target.threads', 5)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scanner.scan) for scanner in recon_scanners]
        concurrent.futures.wait(futures)
        
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logger.error(f"Exception in recon scanner: {e}")
    
    # Check for WAF
    waf_detected = any(vuln['type'] == 'WAF Detected (Active)' or vuln['type'] == 'WAF Detected (Passive)' 
                      for scanner in recon_scanners for vuln in scanner.vulnerabilities)
    
    if waf_detected:
        logger.error("WAF Detected!")
        if not click.confirm("Continue with vulnerability testing?"):
            logger.info("Generating recon-only report...")
            all_vulns = []
            for scanner in recon_scanners:
                all_vulns.extend(scanner.vulnerabilities)
            reporter = Reporter(all_vulns)
            reporter.generate_json()
            reporter.generate_html()
            logger.success("Recon report saved.")
            return
    
    # Crawl for vuln testing
    logger.info("Crawling for forms and URLs...")
    crawler = Crawler(target_url, requester)
    crawler.crawl()
    forms = crawler.forms
    urls = list(crawler.urls)
    logger.info(f"Found {len(urls)} URLs and {len(forms)} forms.")
    
    # Vuln phase
    logger.warning("Running Vulnerability Testing Phase...")
    vuln_scanners = [
      #  SQLIScanner(target_url, requester.session, config),
       # BruteForceScanner(target_url, requester.session, config)
    ]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scanner.scan, forms=forms, urls=urls) for scanner in vuln_scanners]
        concurrent.futures.wait(futures)
        
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logger.error(f"Exception in vuln scanner: {e}")
    
    # Collect all vulnerabilities
    all_vulns = []
    for scanner in recon_scanners + vuln_scanners:
        all_vulns.extend(scanner.vulnerabilities)
        
    logger.success("Scan completed!")
    if all_vulns:
        logger.error(f"Found {len(all_vulns)} issues:")
        for vuln in all_vulns:
            logger.raw(f" - [{vuln['severity']}] {vuln['type']}: {vuln['details']}")
    else:
        logger.success("No issues found.")

    # Generate reports
    reporter = Reporter(all_vulns)
    reporter.generate_json()
    reporter.generate_html()

if __name__ == '__main__':
    main()
