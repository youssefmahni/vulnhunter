import json
import os
from datetime import datetime

class Reporter:
    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.now().isoformat()

    def generate_json(self, output_dir="reports"):
        os.makedirs(output_dir, exist_ok=True)
        report = {
            "timestamp": self.timestamp,
            "vulnerabilities": self.vulnerabilities
        }
        with open(f"{output_dir}/report.json", 'w',encoding='utf-8') as f:
            json.dump(report, f, indent=4)

    def generate_html(self, output_dir="reports"):
        os.makedirs(output_dir, exist_ok=True)
        html = f"""
        <html>
        <head><title>VulnHunter Report</title></head>
        <body>
        <h1>VulnHunter Security Report</h1>
        <p>Generated: {self.timestamp}</p>
        <table border="1">
        <tr><th>Type</th><th>Severity</th><th>Details</th></tr>
        {"".join(f"<tr><td>{v['type']}</td><td>{v['severity']}</td><td>{v['details']}</td></tr>" for v in self.vulnerabilities)}
        </table>
        </body>
        </html>
        """
        with open(f"{output_dir}/report.html", 'w',encoding='utf-8') as f:
            f.write(html)