

import sys

from classification_utils import *
from DNSdep.dns_hardode import *
import validators
import json
from utils import *
from DNSdep.get_ns import *
from get_soa import *
from DNSdep.group_utils import *
import logging
from config import *
# output: rank,website,provider,providerType,optional
        
from collections import defaultdict
log = logging.getLogger(__name__)

def find_if_dns_third(website, ns, concentration, soa_w=None, soa_p=None, san_w=None):

    third = "unknown"
    if(match_TLD(website,ns)):
        return "Pvt"

    if("google" in website and "google" in ns):
       return "Pvt"

    if("azure-dns" in ns and website in microsoft_domains):
        return "Pvt"
        
    if("awsdns" in ns or "ultradns" in ns or "cloudflare" in ns or "domaincontrol" in ns or "dnsv1" in ns or "dnsv2" in ns  or "dnsv3" in ns  or "dnsv4" in ns  or "dnsv5" in ns or "arvancdn" in ns or "xserver.jp" in ns or "webedia-group" in ns or "comlaude-dns" in ns or "nscluster" in ns or "easydns" in ns or "nominalia" in ns or "mydnscloud.com" in ns or "dtag.de" in ns or "alphadnszone.com" in ns or "aziondns" in ns or "arubadns" in ns or "hostdns.co.za" in ns or "first-ns.de" in ns or "mybluehost" in ns or "dnscpanel" in ns or "hostserv.co.za" in ns or "easydns" in ns or "dnsv.jp" in ns or "oraclecloud.net" in ns or "crystalwebhosting" in ns or "bestwebhosting" in ns or "arvancdn" in ns or "reflected.net" in ns or "comlaude" in ns or "nameserver2.co.za" in ns or "nameserver1.co.za" in ns or "nameserver3.co.za" in ns or "nameserver4.co.za" in ns or "managed-ns" in ns or "transip" in ns or "edgecastdns.net" in ns and "1and1-dns" in ns or"eurodns" in ns or "clustereddns" in ns or "zsd.co.za" in ns or "zomerlust" in ns or "turtle.co.za" in ns or "enetworks" in ns or "iewc.co.za" in ns or "clusterdns" in ns or "easyweb.co.za" in ns or "regzone" in ns or "brilliantweb.co.za" in ns or "aasaam.net" in ns or "x-ns.com" in ns or "x-ns.it" in ns or "srv53.net" in ns or "novagraaf" in ns or "naver" in ns or "netuse.de" in ns or "infoedgeindia.net" in ns or "hostdl.com" in ns or "gehirndns" in ns or "gabia" in ns or "d-53." in ns or "active24." in ns or "hichina" in ns or "second-ns." in ns or "esicia.rw" in ns or "kaneza.com" in ns or "liquidtelecom.rw" in ns or "mtnonline.rw" in ns or "afriregister.com" in ns or "beget.pro" in ns or "beget.com" in ns or "contabo.net" in ns or "cscdns.uk" in ns or "dns-h.com" in ns or "host-h.net" in ns or "inhostedns.com" in ns or "liquidweb.com" in ns or "liquidtelecom.net" in ns or "zubahost.com" in ns or "observatoiredesmarques.fr" in ns or "rackspace.com" in ns or "stackdns.com" in ns or "tigertech." in ns or "edrive" in ns or "reg.ru" in ns or "register.it" in ns or "hsmedia.ru" in ns or "perf1.fr" in ns or "rackforest.hu" in ns or "msgafrica.com" in ns or "jtl.co.ke" in ns or "xtranet.co.ke" in ns or "itexpertskenya.co.ke" in ns or "is.co.ke" in ns or "iskenya.co.ke" in ns or "myisp.co.ke" in ns or "jamii.co.ke" in ns or "netimcloud.co.ke" in ns or "bluewebsafrica.co.ke" in ns or "fastly.net" in ns or "gandi.net" in ns or "stackpathdns.net" in ns or "anycast.me" in ns or"ovh.net" in ns or "cdnetdns" in ns or "mojohost.com" in ns or "hover.com" in ns or "townnews.com" in ns or "azure-dns" in ns):
        return "Third"
    
    if(inSAN(website,ns, san_w)):
        return "Pvt"

    if(not soa_w): soa_w = get_SOA(website)
    if(not soa_p): soa_p = get_SOA(ns)

    if(soa_w and soa_p and not match_SOA(soa_w, soa_p)):
        return "Third"
   
    if(concentration[ns] >= 50):
        return "Third"
    
    if(soa_p and match_TLD_website_SOAprovider(website, soa_p)):
        return "Pvt"
    
    if(".gov." in ns):
        return "Pvt"

    if(match_loose_TLD(website,ns)):
        return "Pvt"
   
    
    if(".gov" in ns):
        return "Pvt"
    if(ns in ["twtrdns.net","wikimedia.org","kasperskylabs.net","sky.com","alibabadns.com","theguardiandns.com","thomsonreuters.net","akamaistream.net","rbxinfra.net","apple.com","facebook.com","z5h64q92x9.net","foxdoua.com","dns.fox","quack-dns.com","saudi.net.sa","wal-mart.com","salesforce-dns.com"]):
        return "Pvt"
    
    import re
    if(re.match(r"state\.[a-z]+\.us",ns)):
        return "Pvt"
    
    if(".edu" in ns):
        return "Pvt"
   
    return third     



def check_match(n1,n2,soa_lib):
    grpid = None
    prog = re.compile("ip-[0-9\-]+.eu")
    result1 = prog.match(n1)
    result2 = prog.match(n2)
    prog2 = re.compile("dnsv[0-9].com")
    result3 = prog2.match(n1)
    result4 = prog2.match(n2)
    if(result1 and "ovh" in n2):
        grpid = n2

    elif(result2 and "ovh" in n1):
        grpid = n1

    elif(match_loose_TLD(n1,n2)):
        grpid = tldextract.extract(n1).domain

    elif(match_SOA_addr(n1,n2,soa_lib)):
        grpid =  soa_lib[n1][0]

    elif(match_SOA_contact(n1,n2,soa_lib)):
        grpid =  soa_lib[n1][1]

    if(grpid):
        if(result3 or result4 or "dnsv1.com" in n1 or "dnsv1.com" in n2):
            grpid = "dnspod.com"
    return grpid


def detect_redundancy(nameservers, ns_type, soa_ns, NS_GRP):
    groups = {}
    for k,v in NS_GRP.items():
        groups.setdefault(v, set()).add(k)
    grouped = set()
    for n1 in nameservers:
        for n2 in nameservers:
            if(n1 == n2):
                continue
            if(ns_type[n1] != "Third" or ns_type[n2]!="Third"):
                continue
            grpid = check_match(n1,n2,soa_ns)
            if(grpid):
                grouped.add(n1)
                grouped.add(n2)                    
                if(n1 in NS_GRP and n2 in NS_GRP):
                    gid1 = NS_GRP[n1]
                    gid2 = NS_GRP[n2]
                    if(gid1 == gid2):
                        grpid = gid1
                    else:
                        grpid = gid1
                        for ns_p in groups[gid2]:
                            NS_GRP[ns_p] = gid1
                        
                        new_grp = groups[gid1].union(groups[gid2])
                        groups[gid1] = new_grp
                        del groups[gid2]

                elif(n1 in NS_GRP):
                    grpid = NS_GRP[n1]
                elif(n2 in NS_GRP):
                    grpid = NS_GRP[n2]
                
                NS_GRP[n1] = grpid
                NS_GRP[n2] = grpid
                if(grpid not in groups):
                    groups[grpid] = set()
                groups[grpid].add(n1)
                groups[grpid].add(n2)
    
    return groups, NS_GRP

def get_DNS_details(host: str) -> dict :
   
    if(validators.url(host)):
        host = get_hostname_from_url(host)
    
    valid_input = check_if_valid(host)
   
    if(valid_input):
        name_servers = get_NS(host)
        return name_servers

    else:
        log.exception(f"Invalid input {host}")
        raise Exception(f"Invalid input {host}")

def read_DNS_concentration():
    f = open(f"{PARENT_DIR_PATH}/DNSdep/last_DNS_data","r")
    conc = defaultdict(int)
    for line in f:
        line = line.strip().split(",")
        ns = line[2]
        conc[ns] += 1
    return conc

def classify(website,ns,soa_w=None, soa_p=None, san_w=None):

    
    output = "unknown"
    concentration = read_DNS_concentration()
    output = find_if_dns_third(website, ns, concentration, soa_w,soa_p, san_w)
    
    return output

def main():
    # check if input given
    
    if(len(sys.argv) < 2):
        raise Exception("\nPlease provide a website name to get its certificate authority details.\n")
    
    
    host = sys.argv[1]
    ns_type, ns_groups = find_and_classify(host)
    for ns, type in ns_type.items():
        if(type=="Third"):
            print(f"{ns},{type},{ns_groups[ns]}")
        else:
            print(f"{ns},{type}")
    # print(host, details["ocsp"], output)
    

def find_and_classify(host: str) -> tuple:
    name_servers = get_DNS_details(host)
    print("name_servers",name_servers)
    soa_ns = {}
    soa_w = get_SOA(host)
    san_w = get_san(host)
    ns_type = {}
    third = 0
    for ns in name_servers:
        if(ns not in soa_ns):
            soa_ns[ns] = get_SOA(ns)
        ns_type[ns] = classify(host, ns, soa_w, soa_ns[ns], san_w)
        if(ns_type[ns] == "Third"):
            third+=1
    print(ns_type)
    ns_groups = {}
    if(third > 0):
        NS_GRPS = read_service_MAP("DNS")
        groups, ns_groups = detect_redundancy(name_servers, ns_type, soa_ns, NS_GRPS)    
    
    ns_grp_relevant = {}
    for ns, type in ns_type.items():
        if(type == "Third"):
            ns_grp_relevant[ns] = ns_groups[ns]
    return ns_type, ns_grp_relevant

if __name__ == "__main__":
    import logging.config
    logging.config.fileConfig(f'{PARENT_DIR_PATH}/log.conf')
    main()

