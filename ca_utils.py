


import urllib.parse
import logging
import ssl
import socket
log = logging.getLogger(__name__)
from utils import *

ssl._create_default_https_context = ssl._create_unverified_context
def get_san(website):
    try:
        cert = getcert((website,443))
        _, san = parse_cert(cert)
        return san
    except Exception as e:
        log.exception(f"Soome error happened when getting cert for {website} in get_san, {str(e)}")
        return None


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



def add_CA_to_OCSP_NAMES(ocsps: list,ca: str) -> None:
    f = open("OCSP_NAMES","a")
    f.write(f"{ca},{';'.join(ocsps)}\n")
    f.close()


