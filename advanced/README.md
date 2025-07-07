Installation Procedure:

  Way 1:
    1) Create a virtual environment
    2) clone this folder inside the environment
    3) cd into this folder inside the environment
    4) run "pip install -r requirements.txt"
    5) run "apt-get update && \
      apt-get install -y --no-install-recommends \
          whois \
          nmap \
          curl \
          dnsutils \
          iputils-ping \
          build-essential \
          gcc \
          git \
      && apt-get clean \
      && rm -rf /var/lib/apt/lists/*"
     6) The advanced_recon python file can be run now
     
    Way 2:
     1) install docker
     2) clone this folder
     3) cd into this folder
     4) run "docker build advanced_recon ."
     5) run "docker run advanced_recon"
     6) now the advanced_recon.py can be run through docker

Usage Guidelines: 
  advanced_recon.py [-h] [--subdo] [--dns] [--whois] [--headers] [--robotssitemap] [--geoip] [--portscan] [--techdetect] [--emails] [--shodan] [--shodan-key SHODAN_KEY] [--waf]
                         [--output] [--all]
                         domain

  "Advanced Recon Toolkit"
  
  Positional arguments:
    domain                Target domain name
  
  Options:
    -h, --help            show this help message and exit
    --subdo               Enumerates Subdomains
    --dns                 Finds DNS Info
    --whois               Finds whois output for the given domain
    --headers             Finds header info about the given domain
    --robotssitemap       Extracts robots.txt and sitemap.xml file from the domain
    --geoip               Extracts the geoip info of the domain
    --portscan            Scans for ports and banners using nmap
    --techdetect          detects technology using whatweb
    --emails              Harvests the emails attached to the domain
    --shodan              Uses shodan for detailed service info
    --shodan-key SHODAN_KEY
                          Shodan API Key
    --waf                 Detect WAF/CDN using wafw00f
    --output              Output file (JSON) and (HTML)
    --all                 All flags are enabled
    
  Example:
    advanced_recon.py --dns --output google.com
