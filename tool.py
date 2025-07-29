import whois
import dns.resolver
import requests
import socket
import subprocess
import logging
from datetime import datetime
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# WHOIS Lookup
def whois_lookup(domain):
    try:
        info = whois.whois(domain)
        return str(info)
    except Exception as e:
        msg = f"WHOIS lookup failed: {e}"
        logging.error(msg)
        return msg

# DNS Records
def get_dns_records(domain):
    records = {}
    for record_type in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [r.to_text() for r in answers]
        except Exception:
            records[record_type] = ["Not available or restricted"]
    return records

# Subdomain Enumeration
def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            try:
                data = r.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        if domain in sub:
                            subdomains.add(sub.strip())
            except Exception as e:
                logging.error(f"Subdomain parsing failed: {e}")
                return ["Subdomain response was invalid or blocked"]
    except Exception as e:
        logging.error(f"Subdomain enumeration failed: {e}")
        return ["Subdomain API unreachable or blocked"]
    return list(subdomains) if subdomains else ["No subdomains found or access restricted"]

# Port Scanning with Nmap
def scan_ports_nmap(domain):
    try:
        output = subprocess.check_output(['nmap', '-T4', '-F', domain], stderr=subprocess.DEVNULL).decode()
        return output
    except Exception as e:
        msg = f"Nmap scan failed or blocked: {e}"
        logging.error(msg)
        return msg

# Banner Grabbing
def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner if banner else "No banner returned or restricted"
    except socket.timeout:
        return "Timeout - No response"
    except Exception as e:
        return f"Error: {e}"

# Technology Detection
def detect_technologies(domain):
    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=5)
            return dict(r.headers)
        except:
            continue
    return {"Error": "Could not connect or headers restricted"}

# Write Report
def write_report(domain, data):
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/{domain}_report.txt"
    with open(filename, 'w') as f:
        f.write(f"Recon Report for {domain}\nGenerated: {datetime.now()}\n\n")
        for section in ['whois', 'dns', 'subdomains', 'nmap', 'banners', 'technologies']:
            content = data.get(section, "Module not executed.")
            f.write(f"--- {section.upper()} ---\n")
            if isinstance(content, dict):
                for k, v in content.items():
                    f.write(f"{k}: {v}\n")
            elif isinstance(content, list):
                for item in content:
                    f.write(f"- {item}\n")
            else:
                f.write(f"{content}\n")
            f.write("\n")
    logging.info(f"Report saved as {filename}")

# Main Menu
if __name__ == "__main__":
    domain = input("Enter the target domain (e.g., example.com): ")
    report = {}

    while True:
        print("\n--- Recon Menu ---")
        print("1. WHOIS Lookup")
        print("2. DNS Enumeration")
        print("3. Subdomain Enumeration")
        print("4. Port Scan with Nmap")
        print("5. Banner Grabbing")
        print("6. Technology Detection")
        print("7. Generate Report and Exit")

        choice = input("Select an option (1-7): ")

        if choice == "1":
            print("[+] Running WHOIS lookup...")
            report['whois'] = whois_lookup(domain)
        elif choice == "2":
            print("[+] Running DNS Enumeration...")
            report['dns'] = get_dns_records(domain)
        elif choice == "3":
            print("[+] Running Subdomain Enumeration...")
            report['subdomains'] = get_subdomains(domain)
        elif choice == "4":
            print("[+] Running Nmap Port Scan...")
            report['nmap'] = scan_ports_nmap(domain)
        elif choice == "5":
            print("[+] Running Banner Grabbing...")
            try:
                ip = socket.gethostbyname(domain)
                ports = [80, 443, 21, 22, 25, 3306]
                banners = {port: grab_banner(ip, port) for port in ports}
                report['banners'] = banners
            except socket.gaierror:
                print("[Error] Failed to resolve domain. Skipping banner grabbing.")
                report['banners'] = {"error": "Could not resolve domain to IP"}
        elif choice == "6":
            print("[+] Running Technology Detection...")
            report['technologies'] = detect_technologies(domain)
        elif choice == "7":
            write_report(domain, report)
            print("[✓] Exiting. Report generated.")
            break
        else:
            print("Invalid option. Please choose 1-7.")
