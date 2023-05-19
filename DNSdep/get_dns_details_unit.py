

import sys


from classification_utils import *
import validators
import json
from dns_utils import *
from get_ns import *
from get_soa import *
import logging
# output: rank,website,provider,providerType,optional
        
from collections import defaultdict
log = logging.getLogger(__name__)
HAR_DIR="./harfiles"

def find_if_dns_third(website, ns, soa_w=None, soa_p=None):

    third = "unknown"
    if(match_TLD(website,ns)):
        return "Pvt"

    if("google" in website and "google" in ns):
       return "Pvt"
    
    if("awsdns" in ns or "ultradns" in ns or "cloudflare" in ns or "domaincontrol" in ns or "dnsv1" in ns or "dnsv2" in ns  or "dnsv3" in ns  or "dnsv4" in ns  or "dnsv5" in ns or "arvancdn" in ns or "xserver.jp" in ns or "webedia-group" in ns or "comlaude-dns" in ns or "nscluster" in ns or "easydns" in ns or "nominalia" in ns or "mydnscloud.com" in ns or "dtag.de" in ns or "alphadnszone.com" in ns or "aziondns" in ns or "arubadns" in ns or "hostdns.co.za" in ns or "first-ns.de" in ns or "mybluehost" in ns or "dnscpanel" in ns or "hostserv.co.za" in ns or "easydns" in ns or "dnsv.jp" in ns or "oraclecloud.net" in ns or "crystalwebhosting" in ns or "bestwebhosting" in ns or "arvancdn" in ns or "reflected.net" in ns or "comlaude" in ns or "nameserver2.co.za" in ns or "nameserver1.co.za" in ns or "nameserver3.co.za" in ns or "nameserver4.co.za" in ns or "managed-ns" in ns or "transip" in ns or "edgecastdns.net" in ns and "1and1-dns" in ns or"eurodns" in ns or "clustereddns" in ns or "zsd.co.za" in ns or "zomerlust" in ns or "turtle.co.za" in ns or "enetworks" in ns or "iewc.co.za" in ns or "clusterdns" in ns or "easyweb.co.za" in ns or "regzone" in ns or "brilliantweb.co.za" in ns or "aasaam.net" in ns or "x-ns.com" in ns or "x-ns.it" in ns or "srv53.net" in ns or "novagraaf" in ns or "naver" in ns or "netuse.de" in ns or "infoedgeindia.net" in ns or "hostdl.com" in ns or "gehirndns" in ns or "gabia" in ns or "d-53." in ns or "active24." in ns or "hichina" in ns or "second-ns." in ns or "esicia.rw" in ns or "kaneza.com" in ns or "liquidtelecom.rw" in ns or "mtnonline.rw" in ns or "afriregister.com" in ns or "beget.pro" in ns or "beget.com" in ns or "contabo.net" in ns or "cscdns.uk" in ns or "dns-h.com" in ns or "host-h.net" in ns or "inhostedns.com" in ns or "liquidweb.com" in ns or "liquidtelecom.net" in ns or "zubahost.com" in ns or "observatoiredesmarques.fr" in ns or "rackspace.com" in ns or "stackdns.com" in ns or "tigertech." in ns or "edrive" in ns or "reg.ru" in ns or "register.it" in ns or "hsmedia.ru" in ns or "perf1.fr" in ns or "rackforest.hu" in ns or "msgafrica.com" in ns or "jtl.co.ke" in ns or "xtranet.co.ke" in ns or "itexpertskenya.co.ke" in ns or "is.co.ke" in ns or "iskenya.co.ke" in ns or "myisp.co.ke" in ns or "jamii.co.ke" in ns or "netimcloud.co.ke" in ns or "bluewebsafrica.co.ke" in ns or "fastly.net" in ns or "gandi.net" in ns or "stackpathdns.net" in ns or "anycast.me" in ns or"ovh.net" in ns or "cdnetdns" in ns or "mojohost.com" in ns or "hover.com" in ns or "townnews.com" in ns):
        return "Third"
    
    if(inSAN(website,ns)):
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

    if(match_loose_TLD(website,cname)):
        return "Pvt"
    
    if(ns in ["twtrdns.net","wikimedia.org","kasperskylabs.net","sky.com","alibabadns.com","theguardiandns.com","thomsonreuters.net","akamaistream.net","rbxinfra.net","apple.com","facebook.com","z5h64q92x9.net","foxdoua.com","dns.fox","quack-dns.com","saudi.net.sa","wal-mart.com","salesforce-dns.com"]):
        return "Third"
  
    return third     



def check_match(n1,n2,soa_lib):
    grpid = None
    prog = re.compile("ip-[0-9\-]+.eu")
    result1 = prog.match(n1)
    result2 = prog.match(n2)
    prog2 = re.compile("dnsv[0-9].com")
    result3 = prog2.match(n1)
    result4 = prog2.match(n2)
    # if(result1 or result2):
    #     print("it works", n1,n2)
    #     exit()
    
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
        # print("contact matched",n1,n2,grpid)
    if(grpid):
        if(result3 or result4 or "dnsv1.com" in n1 or "dnsv1.com" in n2):
            grpid = "dnspod.com"
    return grpid

def detect_redundancy(nameservers, soa_ns, ns_types):
    # global matched_soa_addr,matched_tld,matched_soa_contact
    groups = {}
    ns_grpid = {}
    grouped = set()
    for n1 in nameservers:
        for n2 in nameservers:
            if(n1 != n2):
                grpid = check_match(n1,n2,soa_ns)
                if(grpid):
                    grouped.add(n1)
                    grouped.add(n2)                    
                    if(n1 in ns_grpid and n2 in ns_grpid):
                        # print("special case-both already in group",n1,n2,grpid)
                        gid1 = ns_grpid[n1]
                        gid2 = ns_grpid[n2]
                        if(gid1 == gid2):
                            # print("both already in same group",n1,n2, gid1)
                            grpid = gid1
                        else:
                            # print("both in diff group",n1,n2, f"assigning {gid1} to all in {gid2}")
                            grpid = gid1
                            for ns_p in groups[gid2]:
                                ns_grpid[ns_p] = gid1
                            
                            new_grp = groups[gid1].union(groups[gid2])
                            groups[gid1] = new_grp
                            del groups[gid2]

                    elif(n1 in ns_grpid):
                        grpid = ns_grpid[n1]
                        # print("only n1 already grouped",n1,n2, "new group id", grpid)
                    elif(n2 in ns_grpid):
                        # print("only n2 already grouped",n1,n2, "new group id", grpid)
                        grpid = ns_grpid[n2]
                    
                    # print("final gid is",grpid)
                    ns_grpid[n1] = grpid
                    ns_grpid[n2] = grpid
                    if(grpid not in groups):
                        groups[grpid] = set()
                    groups[grpid].add(n1)
                    groups[grpid].add(n2)
    prog = re.compile("ip-[0-9\-]+.eu")

    for ns in nameservers:
        if(ns not in grouped):
            result = prog.match(ns)
            if(result):
                ns_grpid[ns] = "ovh.net"
                groups[ns] = {"ovh.net"}
            elif("dnsv1.com" == ns or "dnsv4.com" == ns):
                ns_grpid[ns] = "dnspod.com"
                groups[ns] = {"dnspod.com"}
            else:
                ns_grpid[ns] = ns
                groups[ns] = {ns}
    return groups,ns_grpid

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


def classify(website,ns,soa_w=None):

    
    output = "unknown"
    output = find_if_dns_third(website, ns, soa_w)
    
    return output

def main():
    # check if input given
    
    if(len(sys.argv) < 2):
        raise Exception("\nPlease provide a website name to get its certificate authority details.\n")
    
    
    host = sys.argv[1]
    print(find_and_classify(host))
    # print(host, details["ocsp"], output)
    

def find_and_classify(host: str) -> tuple:
    name_servers = get_DNS_details(host)
    soa_ns = {}
    soa_w = get_SOA(host)
    ns_type = {}
    for ns in name_servers:
        soa_ns[ns] = get_SOA(ns)
        ns_type[ns] = classify(host, ns, soa_w)
    
    ns_groups = detect_redundancy(name_servers, ns_type, soa_ns)
   
    
    
    return result

if __name__ == "__main__":
    import logging.config
    logging.config.fileConfig('log.conf')
    main()

