

import socket
import ssl
import sys
from ca_utils import *
from utils import *
from get_soa import *
from classification_utils import *
import validators



def check_stapling(host):

    output = subprocess.check_output(["bash","bash-ocsp.sh",host])
    if("OCSP Response Status: successful" in str(output)):
        return True
    return False




def find_if_ca_third(website, ocsp, san, soa_w=None, soa_p=None):

    third = "unknown"
    
    if(match_TLD(website,ocsp)):
        return "Pvt"

    
    if("google" in website and ".goog" in ocsp):
        return "Pvt"

    if("apple.com" in ocsp or "msocsp.com" in ocsp or "microsoft.com" in ocsp):
        return "Pvt"
    
    if("amazon" in website and "amazontrust" in ocsp):
        return "Pvt"
    
    if("lencr.org" in ocsp or "digicert.com" in ocsp or "amazontrust.com" in ocsp or "pki.goog" in ocsp or "sectigo" in ocsp or "thawte" in ocsp or "dcocsp.cn" in ocsp or "dhimyotis.com" in ocsp or "trust-provider.cn" in ocsp or "netsolssl.com" in ocsp):
        return "Third"
    if(ocsp in san or match_loose_TLD(website,ocsp)):
        return "Pvt"
    
    if(not soa_w): soa_w = get_SOA(website)
    if(not soa_p): soa_p = get_SOA(website)
    if(not match_SOA(soa_w, soa_p)):
        return "Third"
   
    if(match_TLD_website_SOAprovider(website, soa_p)):
        return "Pvt"
    
    if(third == "unknown"):
        if("comodoca" in ocsp or "godaddy" in ocsp or "globalsign" in ocsp or "geotrust" in ocsp or "secomtrust" in ocsp):
            return "Third"
  
    return third     




def get_CA_details(host: str, getSAN=False, san_file=None) -> str :
   
    if(validators.url(host)):
        host = get_hostname_from_url(host)
    
    valid_input = check_if_valid(host)
   
    if(valid_input):
        port = 443
        try:
            # cert = get_cert_node((host, port))
            # details, sans = parse_cert(cert)
            details, sans = get_cert_node((host, port))
            sans = details["san"]
            if(getSAN):
                sans += f",{host}\n"
                f = open(san_file,"a")
                f.write(sans)
                f.close()
            return details, sans
        except ssl.CertificateError as e:
            return ("ssl-certificate-error" + str(e) + "\n"), None
        
        except socket.error as e:
            return("socket-error" + str(e) + "\n"), None

    else:
        raise Exception("Invalid input")


def classify(website, providers, sans):

    
    output = "unknown"
    for p in providers:
        output = find_if_ca_third(website, p, sans)
        if(output != "unknown"):
            break
    
    return output

def main():
    # check if input given
    if(len(sys.argv) < 2):
        raise Exception("\nPlease provide a website name to get its certificate authority details.\n")
    
   
    host = sys.argv[1]
    ocsp_CA = read_service_MAP("CA")
    count = 0
    print(find_and_classify(host, ocsp_CA))
    # print(host, details["ocsp"], output)
    

def find_and_classify(host: str, ocsp_CA: dict) -> tuple:
    details, sans = get_CA_details(host)
    # print(details, sans)
    if(sans):
        output = classify(host, details["ocsp"], sans)
        stapling = str(check_stapling(host))
        for ocsp in details["ocsp"]:
            if(ocsp in ocsp_CA):
                return (host, ocsp_CA[ocsp], output, stapling)
        
        add_CA_to_OCSP_NAMES(details["ocsp"],details["CA"])
        return(host, ocsp, details["CA"], output, stapling)
    else:
        log.error("get_ca_details incurred some error")

if __name__ == "__main__":
    import logging.config
    logging.config.fileConfig('../log.conf')
    main()

