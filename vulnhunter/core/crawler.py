from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import concurrent.futures
import threading
from core.logger import logger

class Crawler:
    def __init__(self, base_url, requester, max_depth=2, max_urls=100, max_workers=10):
        self.base_url = base_url
        self.requester = requester
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.max_workers = max_workers
        
        self.visited = set()
        self.forms = []
        self.urls = set()
        self.api_endpoints = set()
        
        self.lock = threading.Lock()
        self.logger = logger

    def crawl(self):
        # Queue of (url, depth)
        queue = [(self.base_url, 0)]
        self.visited.add(self.base_url)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # We need to manage the queue dynamically. 
            # Since ThreadPoolExecutor doesn't support a shared queue easily for recursive tasks without waiting,
            # we will use a slightly different approach: submit tasks and collect new links to submit.
            
            # Initial task
            futures = {executor.submit(self.process_url, self.base_url, 0): (self.base_url, 0)}
            
            while futures:
                # Wait for at least one future to complete
                done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                
                for future in done:
                    url, depth = futures.pop(future)
                    try:
                        new_links = future.result()
                        # If we haven't reached max depth, submit new links
                        if depth < self.max_depth:
                            for link in new_links:
                                with self.lock:
                                    if link not in self.visited and len(self.urls) < self.max_urls:
                                        self.visited.add(link)
                                        futures[executor.submit(self.process_url, link, depth + 1)] = (link, depth + 1)
                    except Exception as e:
                        self.logger.error(f"Error crawling {url}: {e}")

    def process_url(self, url, depth):
        self.logger.info(f"Crawling: {url} (Depth: {depth})")
        
        with self.lock:
            self.urls.add(url)
            
        response = self.requester.get(url)
        if not response:
            return []
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract forms
        local_forms = []
        for form in soup.find_all('form'):
            local_forms.append({
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': [{'name': inp.get('name'), 'type': inp.get('type')} for inp in form.find_all('input')]
            })
        
        with self.lock:
            self.forms.extend(local_forms)
        
        # Extract potential API endpoints
        local_api = set()
        for script in soup.find_all('script', src=True):
            src = urljoin(url, script['src'])
            if 'api' in src.lower():
                local_api.add(src)
        
        api_patterns = [r'/api/[^\'"]*', r'/v\d+/[^\'"]*']
        for pattern in api_patterns:
            matches = re.findall(pattern, response.text)
            for match in matches:
                local_api.add(urljoin(url, match))
                
        with self.lock:
            self.api_endpoints.update(local_api)

        # Extract links for next iteration
        new_links = []
        for link in soup.find_all('a', href=True):
            next_url = urljoin(url, link['href'])
            # Remove fragment
            next_url = next_url.split('#')[0]
            
            if self._is_same_domain(next_url):
                 new_links.append(next_url)
                 
        return new_links

    def _is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc