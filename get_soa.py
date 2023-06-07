
import subprocess
import logging
from utils import *

log = logging.getLogger(__name__)



def format_output(output: str) -> tuple:
    output = output.strip()
    if(output):
        
        output = output.split(" ")
        if(len(output) == 1):
            return get_SOA(output[0])
        else:
            server =  get_domain_from_subdomain(output[0].strip("."))
            contact = get_domain_from_subdomain(output[1].strip("."))

            return (server, contact)
    

def get_SOA(domain: str) -> tuple:
    # print("domain soa", domain)
    output = None
    try:
        output = subprocess.check_output(['dig',"soa",domain, '+short'], timeout=30)
        output = str(output, 'utf-8').replace("\n",",").strip(",")
        if 'NXDOMAIN' in output:
            log.error(domain + ",unexpected NX domain error when getting SOA record\n")
        elif(output == ""):
            output = subprocess.check_output(['dig', "soa", "www." + domain, '+short'],timeout=30)
            output = str(output, 'utf-8').replace("\n",",").strip(",")
            return format_output(output)
        elif 'SERVFAIL' in output:
            log.error(domain + ",unexpected SERVFAIL error when getting SOA record\n")
        else:
            return format_output(output)

    except subprocess.CalledProcessError as e:
        log.exception(domain + "," + str(e.output) + "\n")
        return output

