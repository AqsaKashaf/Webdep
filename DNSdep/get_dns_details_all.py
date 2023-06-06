import sys
from get_crux import *
from get_dns_details_unit import *

from config import *

def main():
    # check if input given
    country = "us"
    # if(len(sys.argv) < 2):
    #     raise Exception("Please provide an output file path")
    
    
    if(len(sys.argv) > 1):
        country = sys.argv[1]
        if(not check_valid_country(country)):
            raise Exception("Please enter a valid country code, {country} is not valid")
    
    output_file_path = f"{PARENT_DIR_PATH}/DNSdep"
    month = get_last_month()
    websites = extract_crux_file(country, month)
    results = []
    count = 0
    for r,w in websites:
        ns_type, ns_groups = find_and_classify(w)
        for ns, type in ns_type.items():
            if(type=="Third"):
                results.append((r,w,ns_groups[ns],type))
            else:
                results.append((r,w,ns,type))
        
        count+=1
        if(count == 5):
            write_results(output_file_path,country,"dns",month,results)
            results = {}
            count = 0
            exit()


        

if __name__ == "__main__":
    import logging.config
    logging.config.fileConfig(f'{PARENT_DIR_PATH}/log.conf')
    main()