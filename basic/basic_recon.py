import argparse
import socket
import requests
import dns.resolver
import whois
import subprocess

def subdomain_enumeration(domain):
    subdomains = []
    try:
        url ="https://crt.sh/?q="+domain
        r = requests.get(url)
        for i in r.text.split("<"):
            if len(i.strip()) > 3 and i[2] == ">" and "." in i:
                val = i[3:]
                if val not in subdomains:
                    subdomains.append(val)
    except Exception as e:
        return f"Subdomain Enumeration Error: {e}"
    if subdomains[0]=="It is not currently possible to sort and paginate large result sets efficiently, so only a random subset is shown below.  ":
        return(subdomains[2:])
    return subdomains

def dnsrecord(domain):
    records = {}
    try:
        for rec_type in ['A', 'AAAA', 'NS', 'MX']:
            try:
                answers = dns.resolver.resolve(domain, rec_type)
                records[rec_type] = [str(r) for r in answers]
            except:
                records[rec_type] = []
    except Exception as e:
        return f"DNS Lookup Failed: {e}"
    return records

def whoispy(domain):
    try:
        w = whois.whois(domain)
        if w.text=="":
            raise Exception
        return w.text
    except Exception:
        try:
            result = subprocess.run(["whois", domain], capture_output=True, text=True)
            r=result.stdout
            r=r.split("\n")
            r=r[60:87]
            j=""
            for i in r:
                j+=i+"\n"
            return j
        except Exception as e:
            return f"WHOIS Error: {e}"

def http_headers(domain):
    try:
        r = requests.get(f"http://{domain}")
        return dict(r.headers)
    except Exception as e:
        return {"Error": str(e)}

def robot_sitemap(domain):
    output = {}
    for i in ['robots.txt', 'sitemap.xml']:
        try:
            r = requests.get(f"http://{domain}/{i}")
            output[i] = r.text if r.status_code == 200 else f"Status Code: {r.status_code}"
        except:
            output[i] = "Request Failed"
        output[i] = output[i].split("\n")
        j = len(output[i]) - 1
        while j > 0:
            if output[i][j].startswith("#") or output[i][j] == "":
                output[i].pop(j)
            j = j - 1
    return output

def geoip_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(f"http://ip-api.com/json/{ip}")
        return r.json()
    except Exception as e:
        return {"GeoIP Error": str(e)}

def save_report(domain, report_data):
    filename = f"basic_{domain}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_data)
    print(f"Report saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Recon Toolkit")
    parser.add_argument("domain", help="Target domain name")

    parser.add_argument("--subdo", action="store_true", help="Enumerates Subdomains")
    parser.add_argument("--dns", action="store_true", help="Finds DNS Info")
    parser.add_argument("--whois", action="store_true", help="Finds whois output for the given domain")
    parser.add_argument("--headers", action="store_true", help="Finds header info about the given domain")
    parser.add_argument("--robotssitemap", action="store_true", help="Extracts robots.txt and sitemap.xml file from the domain")
    parser.add_argument("--geoip", action="store_true", help="Extracts the geoip info of the domain")
    parser.add_argument("--all", action="store_true", help="All flags are enabled")

    args = parser.parse_args()
    report = ""

    if args.subdo:
        report += "Enumerating subdomains...\n"
        report += "-------------------------\n"
        report += f"{subdomain_enumeration(args.domain)}\n\n"

    if args.dns:
        report += "Fetching DNS records...\n"
        report += "-----------------------\n"
        report += f"{dnsrecord(args.domain)}\n\n"

    if args.whois:
        report += "Getting WHOIS info...\n"
        report += "---------------------\n"
        report += f"{whoispy(args.domain)}\n\n"

    if args.headers:
        report += "Fetching HTTP headers...\n"
        report += "------------------------\n"
        report += f"{http_headers(args.domain)}\n\n"

    if args.robotssitemap:
        report += "Fetching robots.txt and sitemap.xml...\n"
        report += "--------------------------------------\n"
        report += f"{robot_sitemap(args.domain)}\n\n"

    if args.geoip:
        report += "Performing GeoIP lookup...\n"
        report += "--------------------------\n"
        report += f"{geoip_lookup(args.domain)}\n\n"

    if args.all:
        report += "-------------------------\n"
        report += "Enumerating subdomains...\n"
        report += "-------------------------\n"
        report += f"{subdomain_enumeration(args.domain)}\n\n"
        report += "-----------------------\n"
        report += "Fetching DNS records...\n"
        report += "-----------------------\n"
        report += f"{dnsrecord(args.domain)}\n\n"
        report += "---------------------\n"
        report += "Getting WHOIS info...\n"
        report += "---------------------\n"
        report += f"{whoispy(args.domain)}\n\n"
        report += "------------------------\n"
        report += "Fetching HTTP headers...\n"
        report += "------------------------\n"
        report += f"{http_headers(args.domain)}\n\n"
        report += "--------------------------------------\n"
        report += "Fetching robots.txt and sitemap.xml...\n"
        report += "--------------------------------------\n"
        report += f"{robot_sitemap(args.domain)}\n\n"
        report += "--------------------------\n"
        report += "Performing GeoIP lookup...\n"
        report += "--------------------------\n"
        report += f"{geoip_lookup(args.domain)}\n\n"

    if report:
        save_report(args.domain, report)
        print("Completed Recon")
    else:
        print("No options selected. Use -h for help.")

if __name__ == "__main__":
    main()
