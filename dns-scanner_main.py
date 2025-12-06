import dns.resolver
import dns.query
import dns.zone
import socket
import requests

class DNSScanner:
    def __init__(self, domain):
        self.domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
        print(f"\n[*] Starting DNS scan for: {self.domain}\n")

    # -------------------------------------------
    # A + AAAA RECORDS
    # -------------------------------------------
    def a_records(self):
        print("[+] A / AAAA Records:")
        try:
            ipv4 = socket.gethostbyname(self.domain)
            print(f"  - IPv4: {ipv4}")
        except:
            print("  - No IPv4 found")

        try:
            ipv6_info = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
            if ipv6_info:
                ipv6 = ipv6_info[0][4][0]
                print(f"  - IPv6: {ipv6}")
        except:
            print("  - No IPv6 found")
        print()

    # -------------------------------------------
    # NS RECORDS
    # -------------------------------------------
    def ns_records(self):
        print("[+] NS Records:")
        try:
            ns = dns.resolver.resolve(self.domain, "NS")
            for r in ns:
                print(f"  - {r.to_text()}")
        except:
            print("  - No NS records found")
        print()

    # -------------------------------------------
    # MX RECORDS
    # -------------------------------------------
    def mx_records(self):
        print("[+] MX Records:")
        try:
            mx = dns.resolver.resolve(self.domain, "MX")
            for r in mx:
                print(f"  - {r.exchange} (priority {r.preference})")
        except:
            print("  - No MX records found")
        print()

    # -------------------------------------------
    # TXT RECORDS
    # -------------------------------------------
    def txt_records(self):
        print("[+] TXT Records:")
        try:
            txt = dns.resolver.resolve(self.domain, "TXT")
            for r in txt:
                print(f"  - {r.to_text()}")
        except:
            print("  - No TXT records found")
        print()

    # -------------------------------------------
    # CNAME RECORDS
    # -------------------------------------------
    def cname_record(self):
        print("[+] CNAME Record:")
        try:
            cname = dns.resolver.resolve(self.domain, "CNAME")
            for r in cname:
                print(f"  - {self.domain} → {r.target}")
        except:
            print("  - No CNAME record found")
        print()

    # -------------------------------------------
    # PTR (reverse lookup)
    # -------------------------------------------
    def ptr_record(self):
        print("[+] Reverse DNS (PTR):")
        try:
            ipv4 = socket.gethostbyname(self.domain)
            ptr = socket.gethostbyaddr(ipv4)
            print(f"  - {ipv4} → {ptr[0]}")
        except:
            print("  - No PTR record found")
        print()

    # -------------------------------------------
    # DNSSEC
    # -------------------------------------------
    def dnssec_check(self):
        print("[+] DNSSEC:")
        try:
            dns.resolver.resolve(self.domain, "DNSKEY")
            print("  - DNSSEC: ENABLED")
        except:
            print("  - DNSSEC: NOT ENABLED")
        print()

    # -------------------------------------------
    # Zone Transfer Test (AXFR)
    # -------------------------------------------
    def zone_transfer(self):
        print("[+] Zone Transfer Test (AXFR):")
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                ns_server = ns.to_text()
                print(f"  - Testing NS: {ns_server}")

                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, self.domain))
                    print("    [!] Zone transfer successful (CRITICAL)")
                    for name, node in zone.nodes.items():
                        print("     ->", name.to_text())
                    print()
                except:
                    print("    - Zone transfer not allowed\n")
        except:
            print("  - Could not retrieve NS for AXFR test\n")

    # -------------------------------------------
    # Cloud Provider Detection
    # -------------------------------------------
    def cloud_provider(self):
        print("[+] Cloud Provider Fingerprint:")
        try:
            ipv4 = socket.gethostbyname(self.domain)
            ptr = socket.gethostbyaddr(ipv4)[0].lower()

            if "amazonaws" in ptr:
                print("  - Hosted on AWS")
            elif "cloudflare" in ptr:
                print("  - Using Cloudflare")
            elif "google" in ptr:
                print("  - Hosted on Google Cloud")
            elif "azure" in ptr or "microsoft" in ptr:
                print("  - Hosted on Azure")
            else:
                print(f"  - Provider unknown: {ptr}")
        except:
            print("  - Could not determine provider")
        print()

    # -------------------------------------------
    # Passive Subdomain Enumeration via crt.sh
    # -------------------------------------------
    def passive_enum(self):
        print("[+] Passive Subdomain Enumeration (crt.sh):")

        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = requests.get(url, timeout=10)

            if r.status_code != 200:
                print("  - crt.sh unavailable\n")
                return

            subdomains = set()

            for entry in r.json():
                name = entry["name_value"]
                if "*" not in name:
                    subdomains.add(name)

            for s in sorted(subdomains):
                print(f"  - {s}")

            print(f"\n  Total found: {len(subdomains)}\n")

        except:
            print("  - Could not fetch subdomains\n")

    # -------------------------------------------
    # Subdomain Takeover (non-destructive check)
    # -------------------------------------------
    def takeover_check(self):
        print("[+] Subdomain Takeover Check:")

        takeover_patterns = {
            "amazonaws.com": "S3 bucket potential takeover",
            "herokuapp.com": "Heroku app takeover",
            "github.io": "GitHub pages takeover",
            "cloudfront.net": "CloudFront takeover"
        }

        try:
            cname = dns.resolver.resolve(self.domain, "CNAME")
            target = cname[0].target.to_text().lower()

            for pattern, alert in takeover_patterns.items():
                if pattern in target:
                    print(f"  [!] Possible takeover risk: {target} → {alert}")
                    return

            print("  - No takeover patterns detected")
        except:
            print("  - No CNAME → No takeover risk")
        print()

    # -------------------------------------------
    # Run everything
    # -------------------------------------------
    def run(self):
        self.a_records()
        self.ns_records()
        self.mx_records()
        self.txt_records()
        self.cname_record()
        self.ptr_record()
        self.dnssec_check()
        self.zone_transfer()
        self.cloud_provider()
        self.passive_enum()
        self.takeover_check()


# -------------------------------------------
# Run Scanner
# -------------------------------------------
if __name__ == "__main__":
    target = input("Enter domain: ")
    scanner = DNSScanner(target)
    scanner.run()
