Installation Procedure:
  1) Create a virtual environment
  2) clone this folder inside the environment
  3) cd into this folder inside the environment
  4) run "pip install -r requirements.txt"
  5) pip install whatweb
  6) pip install python-nmap
  7) pip install whois
  8) pip install theharvester
  9) The basic_recon python file can be run now

Usage Guidelines: 
  intermediate_recon.py [-h] [--subdo] [--dns] [--whois] [--headers] [--robotssitemap] [--geoip] [--portscan] [--techdetect] [--emails] [--shodan] [--output] [--all] domain

  "Intermediate Recon Toolkit"
  
  Positional arguments:
    domain           Target domain name
  
  Options:
    -h, --help       show this help message and exit
    --subdo          Enumerates Subdomains
    --dns            Finds DNS Info
    --whois          Finds whois output for the given domain
    --headers        Finds header info about the given domain
    --robotssitemap  Extracts robots.txt and sitemap.xml file
                     from the domain
    --geoip          Extracts the geoip info of the domain
    --portscan       Scans for ports and banners using nmap
    --techdetect     detects technology using whatweb
    --emails         Harvests the emails attached to the domain
    --shodan         Uses shodan for detailed service info
    --output         Output file (JSON)
    --all            All flags are enabled

  Example:
    intermediate_recon.py --dns --output google.com
