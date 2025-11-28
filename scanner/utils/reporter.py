import json
import os
from datetime import datetime

class Reporter:
    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def generate_json(self, output_dir="reports"):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        filename = f"{output_dir}/scan_report_{self.timestamp}.json"
        
        report_data = {
            "timestamp": self.timestamp,
            "vulnerabilities_count": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=4)
            
        print(f"[*] JSON Report saved to: {filename}")

    def generate_html(self, output_dir="reports"):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        filename = f"{output_dir}/scan_report_{self.timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AllSafe Scan Report - {self.timestamp}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                .vuln {{ border: 1px solid #ddd; padding: 10px; margin-bottom: 10px; border-radius: 5px; }}
                .High {{ border-left: 5px solid #e74c3c; }}
                .Medium {{ border-left: 5px solid #f39c12; }}
                .Low {{ border-left: 5px solid #3498db; }}
                .Info {{ border-left: 5px solid #2ecc71; }}
                .Critical {{ border-left: 5px solid #8e44ad; }}
            </style>
        </head>
        <body>
            <h1>AllSafe Scan Report</h1>
            <p>Date: {self.timestamp}</p>
            <p>Total Vulnerabilities: {len(self.vulnerabilities)}</p>
            <hr>
        """
        
        for vuln in self.vulnerabilities:
            html_content += f"""
            <div class="vuln {vuln['severity']}">
                <h3>[{vuln['severity']}] {vuln['type']}</h3>
                <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                <p><strong>Details:</strong> {vuln['details']}</p>
            </div>
            """
            
        html_content += """
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
            
        print(f"[*] HTML Report saved to: {filename}")
