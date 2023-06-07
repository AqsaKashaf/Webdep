
import subprocess
import logging
from utils import *
log = logging.getLogger(__name__)



def format_output(output: str) -> tuple:
    output = output.split(",")
    result = []
    for i in output:
        i = i.strip(".")
        i = get_domain_from_subdomain(i)
        result.append(i)

    return result

def get_NS(domain: str) -> tuple:
    output = None
    try:
        output = subprocess.check_output(['dig',"ns",domain, '+short'],timeout=30)
        output = str(output, 'utf-8').replace("\n",",").strip(",")
        if 'NXDOMAIN' in output:
            log.error(domain + ",unexpected NX domain error when getting NS record\n")
        elif(output == ""):
            output = subprocess.check_output(['dig', "ns", "www." + domain, '+short'],timeout=30)
            output = str(output, 'utf-8').replace("\n",",").strip(",")
            if(output == ""):
                domain = get_domain_from_subdomain(domain)
                output = subprocess.check_output(['dig', "ns", domain, '+short'], timeout=30)
                output = str(output, 'utf-8').replace("\n",",").strip(",")
                return format_output(output)
            return format_output(output)
        
        elif 'SERVFAIL' in output:
            log.error(domain + ",unexpected SERVFAIL error when getting NS record\n")
        else:
            return format_output(output)

    except subprocess.CalledProcessError as e:
        log.exception(domain + "," + str(e.output) + "\n")
        return output

