from modules.base import BaseScanner
import random
import string
import re
from urllib.parse import urlparse, urljoin


class CloudStorage(BaseScanner):
    
    # Common bucket patterns to search for in links/responses
    CLOUD_PATTERNS = {
        'AWS_S3': r'\.s3[\w\d\-\.]*?\.amazonaws\.com',
        'AZURE_BLOB': r'\.blob\.core\.windows\.net',
        'GCP_STORAGE': r'storage\.googleapis\.com'
    }

    # AWS Metadata Endpoint (internal IP for SSRF testing)
    AWS_METADATA_URL = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Starting Cloud Storage and SSRF check on {self.target_url}")
        
        # --- 1. SSRF Check (Internal Misconfiguration) ---
        self._test_ssrf_metadata_exposure()
        
        # --- 2. External Bucket Misconfiguration Check ---
        
        urls_to_test = list(urls or [])
        # Add the main target in case it is a cloud bucket URL itself
        if self.target_url not in urls_to_test:
            urls_to_test.append(self.target_url)

        # Identify all potential cloud storage URLs from the list provided by the crawler
        cloud_targets = self._identify_cloud_targets(urls_to_test)
        
        for url in cloud_targets:
            self._test_cloud_permissions(url)


    def _identify_cloud_targets(self, urls):
        """Identifies URLs that match cloud storage patterns."""
        targets = set()
        for url in urls:
            for provider, pattern in self.CLOUD_PATTERNS.items():
                # Check the domain name of the URL for the pattern
                if urlparse(url).netloc and re.search(pattern, url, re.IGNORECASE):
                    targets.add(url)
                    break
        return list(targets)


    def _test_cloud_permissions(self, bucket_url):
        """Tests a single cloud storage URL for public read and write access."""
        self.logger.info(f"Testing permissions for bucket: {bucket_url}")
        
        # Use the base URL for listing checks
        base_url = urlparse(bucket_url)._replace(path='/').geturl()
        
        # --- A. Test Unauthorized Read/List Access ---
        self._test_read_access(base_url)

        # --- B. Test Unauthorized Write Access ---
        random_filename = 'vulnhunter_test_' + ''.join(random.choices(string.ascii_lowercase, k=8)) + '.txt'
        test_object_url = urljoin(bucket_url, random_filename)
        self._test_write_access(test_object_url)


    def _test_read_access(self, url):
        """Tests for public read (listing) access by checking for list content in a 200 response."""
        
        response = self.session.get(url, allow_redirects=False)
        
        if response and response.status_code == 200:
            content = response.text.lower()
            
            # Common indicators of a successful, public listing (AWS S3, Azure/GCP formats)
            if '<listbucketresult>' in content or '<listblobsresponse>' in content or 'contents' in content:
                self.add_vulnerability(
                    "Cloud Storage Misconfiguration - Public Read/List Access",
                    f"The storage resource at {url} allows unauthorized listing of contents. Data paths and structure are exposed.",
                    "High"
                )
            else:
                self.logger.info("Read/List Check: Bucket is likely closed or empty.")
        elif response and response.status_code == 403:
            self.logger.info("Read/List Check: Server correctly denies access (HTTP 403 Forbidden).")
        else:
            self.logger.info(f"Read/List Check: Received status code {response.status_code if response else 'N/A'}.")

    def _test_write_access(self, test_object_url):
        """Tests for public write access by attempting to upload a test file via PUT."""
        
        test_payload = b"VulnHunter-Write-Test"
        
        try:
            # PUT method is standard for object creation
            response = self.session.request('PUT', test_object_url, data=test_payload, allow_redirects=False)

            if response and response.status_code in [200, 201, 204]:
                # Successful upload - **high VULNERABILITY**
                
                # Attempt to delete the test file immediately to clean up
                self.session.request('DELETE', test_object_url) 

                self.add_vulnerability(
                    "Cloud Storage Misconfiguration - Public Write/Upload Access",
                    f"The storage resource at {test_object_url} allows unauthorized file upload. This could lead to data injection, DoS, or XSS.",
                    "high"
                )
            else:
                self.logger.info(f"Write Check: Server correctly denies upload (Status: {response.status_code if response else 'N/A'}).")
        
        except Exception as e:
            # Handle connection errors or other issues
            self.logger.error(f"Write Check: Error during PUT request (likely network or missing method): {e}")
            
    def _test_ssrf_metadata_exposure(self):
        """Tests for Server-Side Request Forgery (SSRF) by attempting to access the internal AWS metadata endpoint."""
        
        self.logger.info(f"Checking for Scanner-side access to AWS Metadata Endpoint: {self.AWS_METADATA_URL}")
        self.logger.info("Note: This test reveals if the scanner's host (or a vulnerable application) can access internal cloud resources.")
        
        try:
            # This is a low-latency, non-internet request, so a short timeout is fine
            response = self.session.get(self.AWS_METADATA_URL, timeout=3, allow_redirects=False)
            
            if response and response.status_code == 200:
                content = response.text
                
                # Check for characteristic signs of metadata response
                if 'security-credentials/' in content.lower():
                    self.add_vulnerability(
                        "Server-Side Request Forgery (SSRF) - Metadata Exposure",
                        f"The scanner successfully accessed the AWS metadata endpoint ({self.AWS_METADATA_URL}), which is a sign of an SSRF vulnerability if this was triggered through a web application parameter. **Check for leaked IAM credentials** in the response content.",
                        "Critical"
                    )
                else:
                    self.logger.info("SSRF Check: Endpoint reachable, but response was not the expected metadata.")
            else:
                self.logger.info("SSRF Check: Metadata endpoint is unreachable or denied (Expected on non-AWS hosts).")

        except Exception as e:
            self.logger.info(f"SSRF Check: Request failed (Expected if not running on AWS/VPC). Error: {e}")
