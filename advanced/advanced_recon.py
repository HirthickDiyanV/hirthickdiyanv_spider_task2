import argparse
import socket
import requests
import dns.resolver
import whois
import subprocess
import json
import nmap
import shodan
import os
from jinja2 import Environment, FileSystemLoader

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
            result = subprocess.run(["whois", domain], capture_output=True, text=True, shell=True)
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
        if i=='robots.txt':
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

def port_scan(domain):
    try:
        scanner = nmap.PortScanner()
        results = scanner.scan(domain, arguments='-sV --script=banner')  # -sV for version detection
        return results
    except Exception as e:
        return {"error": str(e)}

def tech_detect(domain):
    try:
        result = subprocess.run("whatweb "+domain, capture_output=True, text=True, shell=True)
        text=result.stdout
        final = ''
        i = 0
        while i < len(text):
            if text[i] == '\x1b':
                i += 1
                if i < len(text) and text[i] == '[':
                    while i < len(text) and not (text[i].isalpha() and text[i] != ' '):
                        i += 1
                    i += 1
                else:
                    i += 1
            else:
                final += text[i]
                i += 1
        final=final.split("\n")
        final=final[0]+"; "+final[1]
        return final
    except Exception as e:
        return f"Tech Detection Error: {e}"

def shodan_lookup(domain,key):
    try:
        ip = socket.gethostbyname(domain)
        api = shodan.Shodan(key)
        host = api.host(ip)
        return {
            "ip": host["ip_str"],
            "org": host.get("org", "n/a"),
            "os": host.get("os", "n/a"),
            "ports": host["ports"],
            "data": host["data"]
        }
    except Exception as e:
        return {"Shodan Error": str(e)}
    
def email_harvest(domain):
    try:
        engines = "baidu,bevigil,bing,bingapi,brave,bufferoverun,censys,certspotter,criminalip,crtsh,dehashed,dnsdumpster,duckduckgo,fullhunt,github-code,hackertarget,hunter,hunterhow,intelx,netlas,onyphe,otx,pentesttools,projectdiscovery,rapiddns,rocketreach,securityTrails,sitedossier,subdomaincenter,subdomainfinderc99,threatminer,tomba,urlscan,virustotal,yahoo,whoisxml,zoomeye,venacus".split(",")
        found_emails = set()

        for engine in engines:
            try:
                result = subprocess.run(["theHarvester", "-d", domain, "-b", engine], capture_output=True, text=True, timeout=90)
                lines = result.stdout.splitlines()

                collecting = False
                for line in lines:
                    if "Emails found:" in line:
                        collecting = True
                        continue  # skip the "Emails found" line itself
                    if collecting:
                        if line.strip() == "":  # stop if blank line or new section
                            break
                        if "-----" in line: # the initial ------- part is avoided
                            continue
                        found_emails.add(line.strip())
            except Exception:
                pass

        return list(found_emails)
    except Exception as e:
        return f"Email Harvest Error: {e}"

def waf_detection(domain):
    try:
        result = subprocess.run(["wafw00f", domain], capture_output=True, text=True)
        r=result.stdout
        r=r.split("\n")
        r=r[16:]
        j=""
        for i in r:
            if i.startswith("["):
                j+=i+"\n"
        j="Wafw00f:"+"\n"+j
        return j
    except Exception as e:
        return f"WAF Detection Error: {e}"

def htmlreport(domain, report):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template("reporttemplate.html")
    output = template.render(domain=domain, report=report)
    with open(f"reports/{domain}.html", "w") as f:
        f.write(output)
    print(f"HTML report saved to reports/{domain}.html")

    
def main():
    parser = argparse.ArgumentParser(description="Advanced Recon Toolkit")
    parser.add_argument("domain", help="Target domain name")

    parser.add_argument("--subdo", action="store_true", help="Enumerates Subdomains")
    parser.add_argument("--dns", action="store_true", help="Finds DNS Info")
    parser.add_argument("--whois", action="store_true", help="Finds whois output for the given domain")
    parser.add_argument("--headers", action="store_true", help="Finds header info about the given domain")
    parser.add_argument("--robotssitemap", action="store_true", help="Extracts robots.txt and sitemap.xml file from the domain")
    parser.add_argument("--geoip", action="store_true", help="Extracts the geoip info of the domain")
    parser.add_argument("--portscan", action="store_true", help="Scans for ports and banners using nmap")
    parser.add_argument("--techdetect", action="store_true", help="detects technology using whatweb")
    parser.add_argument("--emails", action="store_true", help="Harvests the emails attached to the domain")
    parser.add_argument("--shodan",action="store_true", help="Uses shodan for detailed service info")
    parser.add_argument("--waf", action="store_true", help="Detect WAF/CDN using wafw00f")
    parser.add_argument("--output", action="store_true", help="Output file (JSON) and (HTML)")
    parser.add_argument("--all",action="store_true", help="All flags are enabled")

    args = parser.parse_args()
    report = {}

    if args.subdo:
        print("Enumerating subdomains...")
        report['subdomains'] = subdomain_enumeration(args.domain)

    if args.dns:
        print("Fetching DNS records...")
        report['dns'] = dnsrecord(args.domain)

    if args.whois:
        print("Getting WHOIS info...")
        report['whois'] = whoispy(args.domain)

    if args.headers:
        print("Fetching HTTP headers...")
        report['headers'] = http_headers(args.domain)

    if args.robotssitemap:
        print("Fetching robots.txt and sitemap.xml...")
        report['robots_sitemap'] = robot_sitemap(args.domain)

    if args.geoip:
        print("Performing GeoIP lookup...")
        report['geoip'] = geoip_lookup(args.domain)

    if args.portscan:
        print("Performing port scan...")
        report['portscan'] = port_scan(args.domain)

    if args.techdetect:
        print("Detecting technologies...")
        report['techdetect'] = tech_detect(args.domain)

    if args.emails:
        print("Harvesting emails...")
        report['emails'] = email_harvest(args.domain)

    if args.shodan:
        key=input("API Key=")
        print("Performing Shodan Lookup for detailed service info...")
        report['shodan'] = shodan_lookup(args.domain,key)

    if args.waf:
        print("Detecting WAF/CDN...")
        report['waf'] = waf_detection(args.domain)

    if args.output:
        os.makedirs("reports", exist_ok=True)
        with open(f"reports/{args.domain}.json", "w") as f:
            json.dump(report, f, indent=4)
        print(f"Report saved to {args.domain}")
        htmlreport(args.domain, report)
    else:
        print(json.dumps(report, indent=4))

    if args.all:
        print("Enumerating subdomains...")
        report['subdomains'] = subdomain_enumeration(args.domain)
        print("Fetching DNS records...")
        report['dns'] = dnsrecord(args.domain)
        print("Getting WHOIS info...")
        report['whois'] = whoispy(args.domain)
        print("Fetching HTTP headers...")
        report['headers'] = http_headers(args.domain)
        print("Fetching robots.txt and sitemap.xml...")
        report['robots_sitemap'] = robot_sitemap(args.domain)
        print("Performing GeoIP lookup...")
        report['geoip'] = geoip_lookup(args.domain)
        print("Performing port scan...")
        report['portscan'] = port_scan(args.domain)
        print("Detecting technologies...")
        report['techdetect'] = tech_detect(args.domain)
        print("Harvesting emails...")
        report['emails'] = email_harvest(args.domain)
        print("Performing Shodan Lookup for detailed service info...")
        key=input("API Key=")
        report['shodan'] = shodan_lookup(args.domain,key)
        print("Detecting WAF/CDN...")
        report['waf'] = waf_detection(args.domain)
        os.makedirs("reports", exist_ok=True)
        with open(f"reports/{args.domain}.json", "w") as f:
            json.dump(report, f, indent=4)
        print(f"Report saved to {args.domain}")
        htmlreport(args.domain, report)
if __name__ == "__main__":
    main()
