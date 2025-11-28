from scanner.modules.base import BaseScanner
from scanner.core.crawler import Crawler

class SpiderScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting Spidering on {self.target_url}")
        
        crawler = Crawler(self.target_url, self.session)
        crawler.crawl(depth=2) # Default depth, could be configurable
        
        print(f"[*] Spidering completed. Found {len(crawler.visited_urls)} URLs and {len(crawler.forms)} forms.")
        for url in crawler.visited_urls:
            print(f" - {url}")
            self.add_vulnerability(
                "URL Discovered",
                f"Discovered URL: {url}",
                "Info",
                url=url
            )
