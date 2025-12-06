import dns.resolver

domain = "youtube.com"  # Replace with your domain

try:
    cname_records = dns.resolver.resolve(domain, "CNAME")
    for rdata in cname_records:
        print(f"CNAME: {domain} → {rdata.target.to_text()}")
except dns.resolver.NoAnswer:
    print(f"No CNAME record found for {domain}")
except Exception as e:
    print(f"CNAME lookup failed: {e}")
