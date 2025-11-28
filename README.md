# AllSafe - Advanced Web Application Security Scanner

AllSafe is a modular, configuration-driven web application security scanner designed to automate the penetration testing process. It follows a structured methodology divided into four distinct phases, ensuring comprehensive coverage from reconnaissance to exploitation.

## Key Features

- **Multi-threaded Engine**: Fast scanning with configurable concurrency.
- **Headless Crawling**: Uses Playwright to crawl JavaScript-heavy applications (SPAs).
- **Advanced Reporting**: Generates detailed JSON and HTML reports.
- **Modular Architecture**: Easy to extend with new modules.

## Phases & Modules

### Phase 1: Information Gathering (Reconnaissance)
- **Subdomain Enumeration**: Passive enumeration using `crt.sh`.
- **Tech Stack Fingerprinting**: Identifies server technologies and CMS.
- **Directory Brute-forcing**: Discovers hidden directories and files.
- **Spidering/Crawling**: Headless crawling to map the application structure (URLs and forms).
- **Google Dorking**: Generates targeted dorks for manual recon.
- **WAF Detection**: Detects Web Application Firewalls via headers and active payloads.

### Phase 2: Configuration & Deployment Management
- **SSL/TLS Testing**: Checks for weak SSL/TLS versions and cipher suites.
- **Cloud Storage Enumeration**: Scans for open S3 and Azure buckets.
- **Subdomain Takeover**: Detects dangling CNAME records.
- **Security Headers**: Analyzes HTTP headers for security best practices.
- **CORS Misconfiguration**: Tests for insecure CORS policies.

### Phase 3: Identity & Access Management (IAM)
- **Authentication Testing**: Identifies login forms and performs brute-force attacks.
- **Session Management**: Analyzes cookies for security flags (Secure, HttpOnly).
- **Authorization Checks**: Detects potential IDOR vulnerabilities.

### Phase 4: Input Validation
- **SQL Injection (SQLi)**: Tests for Error-based, Boolean-based Blind, and Time-based Blind SQLi.
- **Cross-Site Scripting (XSS)**: Tests for reflected XSS.
- **SSRF**: Checks for Server-Side Request Forgery.
- **XXE**: Checks for XML External Entity vulnerabilities.
- **Command Injection**: Tests for OS command injection.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/allsafe.git
   cd allsafe
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Playwright browsers:**
   ```bash
   playwright install chromium
   ```

4. **Make the script executable:**
   ```bash
   chmod +x allsafe
   ```

## Configuration

AllSafe is driven by a central configuration file `config.yaml`. You can customize the target, timeouts, threads, and wordlist paths here.

```yaml
target:
  url: "http://example.com"
  timeout: 10
  threads: 5  # Number of concurrent threads

wordlists:
  subdomains: "wordlists/subdomains.txt"
  directories: "wordlists/directories.txt"
  users: "wordlists/users.txt"
  passwords: "wordlists/passwords.txt"

scanners:
  sqli:
    payloads: "wordlists/sqli_payloads.txt"
```

## Usage

Run the scanner by specifying the target URL and the desired phase.

### Basic Usage
```bash
./allsafe http://example.com --phase <phase_name>
```

### Phase Examples

**1. Reconnaissance**
```bash
./allsafe http://example.com --phase recon
```

**2. Configuration Checks**
```bash
./allsafe http://example.com --phase config
```

**3. IAM Testing**
```bash
./allsafe http://example.com --phase iam
```

**4. Input Validation**
```bash
./allsafe http://example.com --phase input
```

## Reports

After each scan, reports are automatically generated in the `reports/` directory in both JSON and HTML formats.

## Disclaimer

This tool is for educational and authorized testing purposes only. The author is not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before scanning any target.
