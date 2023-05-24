
def _check_addr_hardcoded_cases(n1,n2,soa_n1_server, soa_n2_server):
    if("cloudflare" in soa_n1_server and "cloudflare" in soa_n2_server):
        return False
            
    if("awsdns" in soa_n1_server and "awsdns" in soa_n2_server):
        if("awsdns" not in n1 or "awsdns" not in n2):
            return False
                
    if("azure-dns.com" in soa_n1_server and "azure-dns.com" in soa_n2_server):
        return False
            
    if("googledomains.com" in soa_n1_server and "googledomains.com" in soa_n2_server):
        return False

    if("nsone.net" in soa_n1_server and "nsone.net" in soa_n2_server):
        return False

    if("domaincontrol.com" in soa_n1_server and "domaincontrol.com" in soa_n2_server):
        if("godaddy" not in n1 or "godaddy" not in n2):
           return False
        
    if("registrar-servers.com" in soa_n1_server and "registrar-servers.com" in soa_n2_server):
        if("namecheap" not in n1 or "namecheap" not in n2):
            return False
    
    if("ovh" in soa_n1_server and "ovh" in soa_n2_server):
        if("anycast.me" not in n1 or "anycast.me" not in n2):
            if("ovhcloud" not in n1 or "ovhcloud" not in n2):
                return False
            
    if("anycast.me" in soa_n1_server and "anycast.me" in soa_n2_server):
        if("ovh" not in n1 or "ovh" not in n2):
            if("ovhcloud" not in n1 or "ovhcloud" not in n2):
                return  False
    if(soa_n1_server.endswith(".") or soa_n2_server.endswith(".")):
            return False
    
    return False
    
def match_SOA_addr(n1,n2,soa_lib):
    match = False
    if("localhost." in n1 or "localhost." in n2):
        return False
    if(n1 in soa_lib and n2 in soa_lib):
        soa_n1_server = soa_lib[n1][0]
        soa_n2_server = soa_lib[n2][0]

        if(soa_n1_server == soa_n2_server):
            return True
            
    return _check_addr_hardcoded_cases(n1,n2,soa_n1_server, soa_n2_server)
            
            
def _check_contact_hardcoded_cases(n1,n2,soa_n1_contact,soa_n2_contact):
    if("hostmaster." == soa_n1_contact or "gmail" in soa_n1_contact or "hotmail" in soa_n1_contact or "nowhere." == soa_n1_contact or "." == soa_n1_contact or "localdomain." == soa_n1_contact):
        return False
    
    elif("hostmaster." == soa_n2_contact or "gmail" in soa_n2_contact or "hotmail" in soa_n2_contact or "nowhere." == soa_n2_contact or "." == soa_n2_contact or "localdomain." == soa_n1_contact):
        return False
    
    if("cloudflare" in soa_n1_contact and "cloudflare" in soa_n2_contact):
        return False
    
    if("nsone.net" in soa_n1_contact and "nsone.net" in soa_n2_contact):
        return False
    
    if("jomax" in soa_n1_contact and "jomax" in soa_n2_contact):
        return False
    
    if("amazon.com" in soa_n1_contact and "amazon.com" in soa_n2_contact):
        if("awsdns" not in n1 or "awsdns" not in n2):
            return False
        
    if("microsoft.com" in soa_n1_contact and "microsoft.com" in soa_n2_contact):
        if("azure-dns" not in n1 or "azure-dns" not in n2):
            return False
        
    if("google.com" in soa_n1_contact and "google.com" in soa_n2_contact):
        if("googledomains.com" not in n1 or "googledomains.com" not in n2):
            return False
        
    if("ovh.net" in soa_n1_contact and "ovh.net" in soa_n2_contact ):
        if(("ovh" not in n1 and "anycast.me" not in n1) or ("ovh" not in n2 and "anycast.me" not in n2)):
            return False
        
    if(soa_n1_contact.endswith(".") or soa_n2_contact.endswith(".")):
        return False
    
    return False

def match_SOA_contact(n1,n2,soa_lib):

    if("localhost." in n1 or "localhost." in n2):
        return False
       
    if(n1 in soa_lib and n2 in soa_lib):
        soa_n1_contact = soa_lib[n1][1]
        soa_n2_contact = soa_lib[n2][1]
        if(soa_n1_contact == soa_n2_contact):
            return True
            
    return _check_contact_hardcoded_cases(n1,n2,soa_n1_contact,soa_n2_contact)

