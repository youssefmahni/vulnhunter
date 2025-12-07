from modules.base import BaseScanner
import os
import time
from datetime import datetime
import concurrent.futures

import random
import string
import os
from datetime import datetime
import concurrent.futures

class DirbScanner(BaseScanner):
    def __init__(self, target_url, session, config=None):
        super().__init__(target_url, session, config)
        self.wildcard_responses = []

    def calibrate(self):
        """
        Detects if the server returns non-404 responses for non-existent URLs (Soft 404).
        """
        self.logger.info("Calibrating for wildcard/soft 404 responses...")
        self.wildcard_responses = []
        
        # Generate a few random non-existent paths
        # Generate a few random non-existent paths
        for _ in range(3):
            random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            
            # Test as file
            url_file = f"{self.target_url}/{random_path}"
            self._probe_wildcard(url_file)
            
            # Test as directory
            url_dir = f"{self.target_url}/{random_path}/"
            self._probe_wildcard(url_dir)
        
        if not self.wildcard_responses:
             self.logger.info("Calibration failed (network error?), assuming no wildcards.")
             return

        # Analyze results
        # If all return 404, we are good.
        non_404s = [r for r in self.wildcard_responses if r['status'] != 404]
        if non_404s:
            self.logger.warning(f"Detected wildcard/soft 404 behavior. {len(non_404s)}/{len(self.wildcard_responses)} checks returned non-404.")
            for r in non_404s:
                self.logger.raw(f"    - Status: {r['status']}, Length: {r['length']}, URL: {r['url']}")
            self.logger.info("Will filter results matching these signatures.")
        else:
            self.logger.info("No wildcard behavior detected (standard 404s).")

    def _probe_wildcard(self, url):
        try:
            resp = self.session.get(url, timeout=self.config.get('dirb_scanner.timeout', 5), allow_redirects=False)
            self.wildcard_responses.append({
                'status': resp.status_code,
                'length': len(resp.content),
                'location': resp.headers.get('Location'),
                'url': url
            })
        except Exception:
            pass

    def is_wildcard(self, status_code, content_length, location=None):
        """
        Checks if a response matches known wildcard signatures.
        """
        for w in self.wildcard_responses:
            # If the wildcard response was a 404, we don't filter based on it 
            if w['status'] == 404:
                continue
            
            # Strict status match
            if status_code == w['status']:
                # Check Location header for redirects
                if status_code in [301, 302, 307, 308]:
                    if w.get('location') != location:
                        continue

                # Loose length match (allow small variance)
                diff = abs(content_length - w['length'])
                
                if w['length'] < 100:
                    if diff <= 5:
                        return True
                elif diff / w['length'] < 0.05:
                    return True
        return False

    def _verify_directory(self, dir_url):
        """
        Verifies if a found directory is real by checking a random non-existent path inside it.
        If the random path returns a 'found' status, the directory is likely a soft-404 trap or a file.
        """
        random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        probe_url = f"{dir_url}{random_path}"
        try:
            resp = self.session.get(probe_url, timeout=self.config.get('dirb_scanner.timeout', 5), allow_redirects=False)
            # If the random path is ALSO found (not 404, not wildcard), then it's a trap.
            if resp.status_code not in [404, 301, 307, 308, 429] and not self.is_wildcard(resp.status_code, len(resp.content), resp.headers.get('Location')):
                return False
            return True
        except Exception:
            return True

    def scan(self, forms=None, urls=None):
        self.logger.info(f"Running DIRB-style directory brute-force on {self.target_url}")

        wordlist_path = self.config.get('wordlists.directories', 'wordlists/directories.txt')
        full_wordlist_path = os.path.join(os.path.dirname(__file__), '..', '..', wordlist_path)

        if not os.path.isfile(full_wordlist_path):
            self.logger.error(f"Wordlist not found: {full_wordlist_path}")
            return

        # Read wordlist
        with open(full_wordlist_path, 'r') as f:
            words = [line.strip() for line in f if line.strip()]

        max_depth = self.config.get('dirb_scanner.max_depth', 3)

        # Perform calibration
        self.calibrate()

        # Scan root
        self.scan_base(self.target_url, words, 0, max_depth)


    def scan_base(self, base_url, words, depth, max_depth):
        found_dirs = []
        
        # Ensure base_url doesn't have trailing slash for consistent joining
        base_url = base_url.rstrip('/')

        def check_word(word):
            local_downloaded = 0
            local_found = 0
            file_reported = False
            
            # Try as file
            file_url = f"{base_url}/{word}"
            try:
                resp = self.session.get(file_url, timeout=self.config.get('dirb_scanner.timeout', 5), allow_redirects=False)
                local_downloaded += 1
                if resp.status_code not in [404, 403, 301, 307, 308, 429] and not self.is_wildcard(resp.status_code, len(resp.content), resp.headers.get('Location')):
                    self.logger.raw(f"+ {file_url} (CODE:{resp.status_code}|SIZE:{len(resp.content)})")
                    self.add_vulnerability(
                        "File Found",
                        f"{file_url} (CODE:{resp.status_code}|SIZE:{len(resp.content)})",
                        "Info"
                    )
                    local_found += 1
                    file_reported = True
            except Exception as e:
                pass

            # Try as directory
            # We check directories even if file was found, as they might be distinct (e.g. API endpoints)
            if True:
                dir_url = f"{base_url}/{word}/"
                try:
                    resp = self.session.get(dir_url, timeout=self.config.get('dirb_scanner.timeout', 5), allow_redirects=False)
                    local_downloaded += 1
                    if resp.status_code not in [404, 301, 307, 308, 429] and not self.is_wildcard(resp.status_code, len(resp.content), resp.headers.get('Location')):
                        # Verify it's a real directory and not a trap
                        if self._verify_directory(dir_url):
                            self.logger.raw(f"==> DIRECTORY: {dir_url}")
                            self.add_vulnerability(
                                "Directory Found",
                                f"{dir_url} (CODE:{resp.status_code}|SIZE:{len(resp.content)})",
                                "Info"
                            )
                            local_found += 1
                            found_dirs.append(dir_url)
                except Exception as e:
                    pass
            return local_downloaded, local_found

        max_workers = self.config.get('dirb_scanner.threads', 10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_word, word) for word in words]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        downloaded = sum(d for d, f in results)
        found_count = sum(f for d, f in results)
        self.logger.raw(f"Downloaded: {downloaded} - Found: {found_count}")

        # Recurse into found directories
        if depth < max_depth:
            for sub_dir in found_dirs:
                self.scan_base(sub_dir, words, depth + 1, max_depth)