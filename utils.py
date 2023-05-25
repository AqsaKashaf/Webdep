


import re
import urllib.parse
import tldextract
import logging
from iso3166 import countries
from datetime import datetime
import dateutil.relativedelta
import socket
import subprocess
log = logging.getLogger(__name__)



  
def run_subprocess(command: list) -> str:
    """Run subprocess with the input command"""
    output = ''
    try:
        output = subprocess.check_output(command)
        output = str(output, 'utf-8')
    except subprocess.CalledProcessError as e:
        log.exception(str(e.output))

    return output



def remove_file(file):
    try:
        pathlib.Path(file).unlink()
    except Exception as e:
        log.exception(f"Trying to remove file {file} failed")

def isIP(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False
    

def get_last_month():
    return (datetime.now() + dateutil.relativedelta.relativedelta(months=-1)).strftime("%Y%m")

def check_valid_country(code: str) -> str:
    data = countries.get(code)
    if(data):
        return data.alpha2.lower()
    return None


def write_results(path, country, service, month, data):
    filename = f"{path}/{country}-{service}-{month}"
    f = open(filename,"a")
    for (r,w),d in data.items():
        try:
            f.write(f"{r},{','.join(d)}\n")
        except Exception as e:
            log.exception(f"some wrror ocurred while writing result {r},{w}, {str(e)}")
    f.close()
    
    



def check_if_valid(host: str) -> bool:
    
    if not 1 < len(host) < 253:
        return False

    # Remove trailing dot
    if host[-1] == '.':
        host = host[0:-1]

    #  Split hostname into list of DNS labels
    labels = host.split('.')

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = re.compile(r'^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

    # Check that all labels match that pattern.
    return all(fqdn.match(label) for label in labels)


def read_service_MAP(service: str) -> dict:
    
    f = open(f"../{service.upper()}dep/{service.upper()}_MAP","r")
    links_provider = {}
    for line in f:
        line = line.strip().lower().split(",")
        provider = line[0]
        links = line[1].split(";")
        for link in links:
            links_provider[link] = provider
    f.close()
    return links_provider

def get_domain_from_subdomain(domain: str) -> str:
    try:
        tld = tldextract.extract(domain)
        domain = tld.domain + "." + tld.suffix
        return domain
    except Exception as e:
        log.exception(f"Error in gettign domain from subdomain tld extract {str(e)}, {domain}")


def get_hostname_from_url(url: str) -> str:
    parsed_url = urllib.parse.urlparse(url)
    return parsed_url.netloc