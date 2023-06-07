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
    try:
        websites = extract_crux_file(country, month)
    except Exception as e:
        log.exception(f"could nto get crux file {str(e)}")
        raise Exception(f"could nto get crux file {str(e)}")

    results = set()
    count = 0
    for r,w in websites:
        try:
            if(count>2000):
                print(r,w)
                ns_type, ns_groups = find_and_classify(w)
                print(ns_type)
                for ns, type in ns_type.items():
                    if(type=="Third"):
                        results.add((r,w,ns_groups[ns],type))
                    else:
                        results.add((r,w,ns,type))
            count+=1
            if(count % 100 == 0):
                write_results_dns(output_file_path,country,"dns",month,results)
                results = set()
        except Exception as e:
            log.exception(f"Some exception occured for website {w}, {str(e)}")
            print(e)
        
    


        

if __name__ == "__main__":
    import logging.config
    logging.config.fileConfig(f'{PARENT_DIR_PATH}/log.conf')
    main()