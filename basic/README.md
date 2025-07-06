Installation Procedure:
  1) Create a virtual environment
  2) clone this folder inside the environment
  3) cd into this folder inside the environment
  4) run "pip install -r requirements.txt"
  5) The basic_recon python file can be run now

Usage Guidelines:
  basic_recon.py [-h] [--subdo] [--dns] [--whois] [--headers] [--robotssitemap] [--geoip] [--all] domain

  "Basic Recon Toolkit"

  Positional arguments:
    domain           Target domain name
  
  Options:
    -h, --help       show this help message and exit
    --subdo          Enumerates Subdomains
    --dns            Finds DNS Info
    --whois          Finds whois output for the given domain
    --headers        Finds header info about the given domain
    --robotssitemap  Extracts robots.txt and sitemap.xml file from the domain
    --geoip          Extracts the geoip info of the domain
    --all            All flags are enabled
