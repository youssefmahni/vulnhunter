# VulnHunter - Advanced Web Application Security Scanner

VulnHunter is a powerful, modular Python CLI tool designed for automated web application security reconnaissance and vulnerability scanning. It performs a comprehensive analysis of a target URL, starting with deep reconnaissance and proceeding to vulnerability testing based on intelligent WAF detection.

## Features

VulnHunter is built with a modular architecture, allowing for easy extension and maintenance.

### 🔍 Reconnaissance Modules
These modules gather critical information about the target before any aggressive testing begins:
- **Basic Info**: Retrieves HTTP headers, server info, and technology stack.
- **WAF Detection**: Identifies the presence of Web Application Firewalls (active and passive detection).
- **Headers Check**: Analyzes HTTP security headers (e.g., CSP, HSTS, X-Frame-Options) for misconfigurations.
- **SSL/TLS Check**: Validates SSL certificates and checks for weak configurations.
- **CORS Analysis**: Tests Cross-Origin Resource Sharing policies for security risks.
- **Whois Lookup**: Fetches domain registration details.
- **Dirb Scanner**: Enumerates directories and files using wordlists.
- **Cloud Storage**: Checks for exposed cloud storage buckets (AWS, GCP, Azure) related to the target.

### 🛡️ Vulnerability Testing Modules
If no WAF is detected (or if the user explicitly approves), VulnHunter proceeds with active vulnerability testing:
- **SQL Injection**: Tests input fields and URLs for SQL injection vulnerabilities.
- **Brute Force**: Attempts to brute-force login forms using configurable wordlists.

### 📊 Reporting
- **JSON Reports**: Detailed machine-readable output.
- **HTML Reports**: User-friendly HTML reports with severity levels and summaries.

## Project Structure

The codebase is organized as follows:

- **`core/`**: Core system components.
  - `config.py`: Configuration management.
  - `crawler.py`: Web crawler for discovering URLs and forms.
  - `logger.py`: Centralized logging utility.
  - `reporter.py`: Generates JSON and HTML reports.
  - `requester.py`: Handles HTTP requests with session management.
- **`modules/`**: Pluggable scanner modules.
  - `recon/`: Reconnaissance modules (Basic Info, WAF, SSL, etc.).
  - `vuln/`: Vulnerability scanning modules (SQLi, Brute Force).
- **`reports/`**: Output directory for generated scan reports.
- **`utils/`**: Utility scripts (e.g., banner display).
- **`wordlists/`**: Text files used for directory enumeration and brute-force attacks.
- **`cli.py`**: The main entry point for the command-line interface.
- **`config.yaml`**: Configuration file for customizing the scanner.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/vulnhunter.git
   cd vulnhunter
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Make the CLI executable (optional):**
   ```bash
   chmod +x cli.py
   ```

## Configuration

VulnHunter is highly configurable via `config.yaml`. Key settings include:

- **Target**:
  - `timeout`: Request timeout in seconds.
  - `threads`: Number of concurrent threads for scanning.
- **Wordlists**: Paths to custom wordlists for subdomains, directories, users, passwords, and payloads.
- **Crawler**:
  - `depth`: Crawling depth.
  - `max_urls`: Maximum number of URLs to crawl.
- **Environment**:
  - `apiKey`: API keys for external services (if required).
- **Dirb Scanner**:
  - `threads`: Specific thread count for directory busting.
  - `max_depth`: Recursion depth for directory discovery.

## Usage

Run the scanner by providing the target URL:

```bash
python cli.py <url>
```

**Example:**
```bash
python cli.py https://example.com
```

### Scan Workflow
1. **Reconnaissance**: The tool runs all enabled recon modules.
2. **WAF Check**: It analyzes results to detect a WAF.
3. **Decision Point**:
   - If a **WAF is detected**, the tool pauses and warns you. You can choose to stop (generating a recon-only report) or proceed (at your own risk).
   - If **no WAF is detected**, it automatically proceeds to vulnerability testing.
4. **Vulnerability Scan**: The crawler finds forms and inputs, which are then tested for SQLi and weak credentials.
5. **Reporting**: Final reports are saved in the `reports/` directory.

## Disclaimer

**VulnHunter is for educational purposes and authorized security testing only.**
Using this tool against systems you do not own or do not have explicit permission to test is illegal. The authors are not responsible for any misuse or damage caused by this tool.