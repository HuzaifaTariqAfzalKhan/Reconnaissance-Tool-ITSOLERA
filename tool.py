import whois
import dns.resolver
import requests
import socket
import subprocess
import logging
from datetime import datetime
import os
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# WHOIS Lookup
def whois_lookup(domain, retries=3):
    for attempt in range(retries):
        try:
            info = whois.whois(domain)
            return str(info)
        except Exception as e:
            logging.warning(f"WHOIS attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(2)
    return "WHOIS lookup failed after multiple attempts."

# DNS Records
def get_dns_records(domain, retries=3):
    records = {}
    for record_type in ['A', 'MX', 'TXT', 'NS']:
        for attempt in range(retries):
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [r.to_text() for r in answers]
                break
            except Exception:
                if attempt == retries - 1:
                    records[record_type] = ["Not available or restricted"]
                else:
                    time.sleep(1)
    return records

# Subdomain Enumeration
def get_subdomains(domain, retries=5):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=25)
            if r.status_code == 200:
                try:
                    data = r.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            if domain in sub:
                                subdomains.add(sub.strip())
                    return list(subdomains) if subdomains else ["No subdomains found or access restricted"]
                except Exception as e:
                    logging.error(f"[ERROR] Subdomain parsing failed: {e}")
                    return ["Subdomain response was invalid or blocked"]
        except requests.exceptions.Timeout:
            logging.warning(f"[WARN] crt.sh timed out. Retrying {attempt + 1}/{retries}...")
            time.sleep(2)
        except Exception as e:
            logging.error(f"[ERROR] Subdomain enumeration failed: {e}")
            return ["Subdomain API unreachable or blocked"]
    return ["Subdomain lookup failed after multiple retries"]

# Port Scanning with Nmap
def scan_ports_nmap(domain, retries=3):
    for attempt in range(retries):
        try:
            output = subprocess.check_output(['nmap', '-T4', '-F', domain], stderr=subprocess.DEVNULL).decode()
            return output
        except Exception as e:
            logging.warning(f"Nmap attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(2)
    return "Nmap scan failed after multiple attempts."

# Banner Grabbing
def grab_banner(ip, port, retries=3):
    for attempt in range(retries):
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            s.close()
            return banner if banner else "No banner returned or restricted"
        except socket.timeout:
            time.sleep(1)
        except Exception as e:
            if attempt == retries - 1:
                return f"Error: {e}"
            time.sleep(1)
    return "No banner retrieved after multiple attempts"

# Technology Detection
def detect_technologies(domain, retries=3):
    for attempt in range(retries):
        for scheme in ["https", "http"]:
            try:
                r = requests.get(f"{scheme}://{domain}", timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                return dict(r.headers)
            except:
                continue
        time.sleep(2)
    return {"Error": "Could not connect or headers restricted after multiple attempts"}

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
    return filename

# Check Report Section
def check_report_section(report_path, section_name):
    try:
        with open(report_path, 'r') as f:
            content = f.read()
            if section_name.upper() in content:
                section_data = content.split(f"--- {section_name.upper()} ---")[1].split('\n\n')[0]
                if "Module not executed" in section_data or "failed" in section_data.lower():
                    print(f"[!] {section_name} module returned no useful data.")
                else:
                    print(f"[✓] {section_name} results successfully added to report.")
    except Exception as e:
        print(f"[Error] Could not verify report section {section_name}: {e}")

# Main Menu
if __name__ == "__main__":
    domain = input("\n🌐 Enter the target domain (e.g., example.com): ")
    report = {}
    resolved_ip = None
    report_path = f"reports/{domain}_report.txt"

    while True:
        print("\n======================")
        print("  🛠️  RECON TOOL MENU")
        print("======================")
        print("1️⃣  WHOIS Lookup")
        print("2️⃣  DNS Enumeration")
        print("3️⃣  Subdomain Enumeration")
        print("4️⃣  Port Scan with Nmap")
        print("5️⃣  Banner Grabbing")
        print("6️⃣  Technology Detection")
        print("7️⃣  Generate Report")
        print("0️⃣  Exit")

        choice = input("\n👉 Select an option (0-7): ")

        if choice == "1":
            print("[+] Running WHOIS lookup...")
            report['whois'] = whois_lookup(domain)
            write_report(domain, report)
            check_report_section(report_path, 'whois')

        elif choice == "2":
            print("[+] Running DNS Enumeration...")
            report['dns'] = get_dns_records(domain)
            write_report(domain, report)
            check_report_section(report_path, 'dns')

        elif choice == "3":
            print("[+] Running Subdomain Enumeration...")
            report['subdomains'] = get_subdomains(domain)
            write_report(domain, report)
            check_report_section(report_path, 'subdomains')

        elif choice == "4":
            print("[+] Running Nmap Port Scan...")
            report['nmap'] = scan_ports_nmap(domain)
            write_report(domain, report)
            check_report_section(report_path, 'nmap')

        elif choice == "5":
            print("[+] Running Banner Grabbing...")
            try:
                if not resolved_ip:
                    resolved_ip = socket.gethostbyname(domain)
                ports = [80, 443, 21, 22, 25, 3306]
                banners = {port: grab_banner(resolved_ip, port) for port in ports}
                report['banners'] = banners
            except socket.gaierror:
                print("[Error] Failed to resolve domain. Skipping banner grabbing.")
                report['banners'] = {"error": "Could not resolve domain to IP"}
            write_report(domain, report)
            check_report_section(report_path, 'banners')

        elif choice == "6":
            print("[+] Running Technology Detection...")
            report['technologies'] = detect_technologies(domain)
            write_report(domain, report)
            check_report_section(report_path, 'technologies')

        elif choice == "7":
            write_report(domain, report)
            print("[✓] Full report generated.")

        elif choice == "0":
            print("[✓] Exiting tool. Goodbye!")
            break

        else:
            print("[!] Invalid option. Please choose 0-7.")
