import json
import os
from datetime import datetime
import urllib.parse

class Reporter:
    def __init__(self, vulnerabilities, target_url):
        self.vulnerabilities = vulnerabilities
        self.target_url = target_url
        self.timestamp = datetime.now().isoformat()
        self.date_str = datetime.now().strftime("%Y-%m-%d")

    def _get_filename(self, extension):
        parsed = urllib.parse.urlparse(self.target_url)
        domain = parsed.netloc or parsed.path
        # Clean domain filename safe
        domain = domain.replace(':', '_')
        return f"{domain}_{self.date_str}.{extension}"

    def generate_json(self, output_dir="reports"):
        os.makedirs(output_dir, exist_ok=True)
        report = {
            "target": self.target_url,
            "timestamp": self.timestamp,
            "vulnerabilities": self.vulnerabilities
        }
        filename = self._get_filename("json")
        with open(f"{output_dir}/{filename}", 'w',encoding='utf-8') as f:
            json.dump(report, f, indent=4)

    def generate_html(self, output_dir="reports"):
        os.makedirs(output_dir, exist_ok=True)
        
        # Define severity order
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        
        # Separate Info from other vulnerabilities
        vuln_items = [v for v in self.vulnerabilities if v['severity'] != 'Info']
        info_items = [v for v in self.vulnerabilities if v['severity'] == 'Info']
        
        # Sort vulnerabilities by severity
        vuln_items.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        html = f"""
        <html>
        <head>
            <title>VulnHunter Report - {self.target_url}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; font-size: 12px; }}
                h1 {{ color: #2c3e50; text-align: center; }}
                .container {{ display: flex; gap: 20px; }}
                .section {{ flex: 1; }}
                h2 {{ color: #34495e; margin-top: 0; font-size: 16px; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; font-size: 11px; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .severity-Critical {{ background-color: #ffcccc; color: #990000; font-weight: bold; }}
                .severity-High {{ background-color: #ffe6cc; color: #cc6600; font-weight: bold; }}
                .severity-Medium {{ background-color: #ffffcc; color: #999900; font-weight: bold; }}
                .severity-Low {{ background-color: #e6ffcc; color: #339900; font-weight: bold; }}
                .severity-Info {{ background-color: #e6f7ff; color: #0066cc; }}
            </style>
        </head>
        <body>
        <h1>VulnHunter Security Report</h1>
        <p style="text-align: center;">Target: {self.target_url}<br>Generated: {self.timestamp}</p>
        
        <div class="container">
            <div class="section">
                <h2>Reconnaissance & Information</h2>
                <table>
                <tr><th>Type</th><th>Details</th></tr>
                {"".join(f"<tr><td>{v['type']}</td><td>{v['details']}</td></tr>" for v in info_items) if info_items else "<tr><td colspan='2'>No information items found.</td></tr>"}
                </table>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
                <table>
                <tr><th>Type</th><th>Severity</th><th>Details</th></tr>
                {"".join(f"<tr><td>{v['type']}</td><td class='severity-{v['severity']}'>{v['severity']}</td><td>{v['details']}</td></tr>" for v in vuln_items) if vuln_items else "<tr><td colspan='3'>No vulnerabilities found.</td></tr>"}
                </table>
            </div>
        </div>
        
        </body>
        </html>
        """
        filename = self._get_filename("html")
        with open(f"{output_dir}/{filename}", 'w',encoding='utf-8') as f:
            f.write(html)