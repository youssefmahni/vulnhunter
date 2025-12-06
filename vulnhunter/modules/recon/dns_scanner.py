from modules.base import BaseScanner
import dns.resolver
import socket



class DNSScanner(BaseScanner):

    def scan(self, forms=None, urls=None):
        print(f"[*] Performing DNS scan on {self.target_url}")

        domain = (
            self.target_url.replace("http://", "")
                           .replace("https://", "")
                           .split("/")[0]
        )

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        # ------------------------------------------------------------
        # Helper function for safe DNS queries
        # ------------------------------------------------------------
        def safe_dns_query(record_type):
            
            try:
                return resolver.resolve(domain, record_type)
            except:
                return None

        # ------------------------------------------------------------
        # A Record (IPv4)
        # ------------------------------------------------------------
        try:
            ipv4 = socket.gethostbyname(domain)
            self.add_vulnerability("DNS A Record (IPv4)", f"{domain} → {ipv4}", "Info")
        except:
            pass

        # ------------------------------------------------------------
        # AAAA Record (IPv6)
        # ------------------------------------------------------------
        try:
            
            ipv6_data = dns.resolver.resolve(domain, "AAAA")
            
            if ipv6_data:
                for rdata in ipv6_data:
                    ipv6 = rdata.address
                    self.add_vulnerability("DNS AAAA Record (IPv6)", f"{domain} → {ipv6}", "Info")
        except:
            pass

        # ------------------------------------------------------------
        # NS Records
        # ------------------------------------------------------------
        ns_records = dns.resolver.resolve(domain, "NS")
        if ns_records:
            for ns in ns_records:
                self.add_vulnerability("DNS NS Record", f"{domain} → {ns.to_text()}", "Info")
    
                

        # ------------------------------------------------------------
        # MX Records
        # ------------------------------------------------------------
        mx_records = dns.resolver.resolve(domain,"MX")
        
        if mx_records:
            for mx in mx_records:
                    mail_server = mx.exchange.to_text()
                    preference = mx.preference
                    self.add_vulnerability(
                    "DNS MX Record",
                    f"{domain} → {mail_server} (Pref: {preference})",
                    "Info"
                )

        # ------------------------------------------------------------
        # TXT Records (SPF, DKIM, verification)
        # ------------------------------------------------------------
        try:
            txt_records = dns.resolver.resolve(domain, "TXT")

            for rdata in txt_records:
                try:
                    # TXT records may contain multiple strings
                    txt_value = " ".join(
                        part.decode("utf-8") if isinstance(part, bytes) else part
                        for part in rdata.strings
                    )

                    self.add_vulnerability("DNS TXT Record", txt_value, "Info")

                except Exception as e:
                    print("TXT parse error:", e)
                    pass

        except Exception:
                pass

        # ------------------------------------------------------------
        # CNAME Records
        # ------------------------------------------------------------
        cname_records = safe_dns_query("CNAME")
        if cname_records:
            for cname in cname_records:
                self.add_vulnerability(
                    "DNS CNAME Record",
                    f"{domain} → {cname.target.to_text()}",
                    "Info"
                )

        # ------------------------------------------------------------
        # PTR (Reverse Lookup)
        # ------------------------------------------------------------
        try:
            ipv4 = socket.gethostbyname(domain)
            ptr = socket.gethostbyaddr(ipv4)
            self.add_vulnerability("DNS PTR Record", f"{ipv4} → {ptr[0]}", "Info")
        except:
            pass

        # ------------------------------------------------------------
        # DNSSEC Check
        # ------------------------------------------------------------
        try:
            dns.resolver.resolve(domain, "DNSKEY")
            self.add_vulnerability("DNSSEC Status", f"{domain} has DNSSEC enabled", "Info")
        except:
            self.add_vulnerability("DNSSEC Status", f"{domain} does NOT have DNSSEC enabled", "Info")

      

