


import re
import urllib.parse
import tldextract
import logging
from iso3166 import countries
from datetime import datetime
import dateutil.relativedelta


log = logging.getLogger(__name__)


def getcert(addr, timeout=None):
    """Retrieve server's certificate at the specified address (host, port)."""
    # it is similar to ssl.get_server_certificate() but it returns a dict
    # and it verifies ssl unconditionally, assuming create_default_context does
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(s, server_hostname=addr[0])
    ssl_sock.connect((addr[0], 443))
    return ssl_sock.getpeercert()


def parse_cert(cert: str) -> dict: 
    result = {}

    result["CA"] = cert["issuer"][1][0][1].replace(" ","")
    if("OCSP" in cert):
        ocsp = cert["OCSP"][0]  
        ocsp_domain = urllib.parse.urlparse(ocsp).netloc
        if(ocsp_domain):
            result["ocsp"] = [ocsp_domain]
   
    if("crlDistributionPoints" in cert):
        crl = cert["crlDistributionPoints"][0]
        crl_domain = urllib.parse.urlparse(crl).netloc
        if(crl_domain):
            result["ocsp"].append(crl_domain)
    
    san_list = cert["subjectAltName"]
    
    san_list = [i[1].replace("*.","") for i in san_list]
    san_list = set([get_domain_from_subdomain(i) for i in san_list])
    sans = ",".join(san_list)

    return result, sans


def get_last_month():
    return (datetime.now() + dateutil.relativedelta.relativedelta(months=-1)).strftime("%Y%m")

def check_valid_country(code: str) -> str:
    data = countries.get(code)
    if(data):
        return data.alpha2.lower()
    return None


def write_results(country, service, month, data):
    filename = f"{country}-{service}-{month}"
    print(filename)
    f = open(filename,"a")
    for (r,w),d in data.items():
        f.write(f"{r},{','.join(d)}\n")
    f.close()
    
    

def add_CA_to_OCSP_NAMES(ocsps: list,ca: str) -> None:
    f = open("OCSP_NAMES","a")
    f.write(f"{ca},{';'.join(ocsps)}\n")
    f.close()

def read_OCSP_NAMES() -> dict:
    f = open("OCSP_NAMES","r")
    ocsp_CA = {}
    for line in f:
        line = line.strip().split(",")
        ocsps = line[1].split(";")
        CA = line[0]
    # print(line)
        for ocsp in ocsps:
            # ocsp = get_domain_from_subdomain(ocsp)
            ocsp_CA[ocsp] = CA
    f.close()
    return ocsp_CA

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