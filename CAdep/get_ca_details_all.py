import sys
from get_crux import *
from get_ca_details_unit import *

from config import *



def main():
    # check if input given
    country = "us"
    if(len(sys.argv) > 1):
        country = sys.argv[1]
        if(not check_valid_country(country)):
            raise Exception("Please enter a valid country code, {country} is not valid")
    
    month = get_last_month()
    
    
    websites = extract_crux_file(country, month)
    ocsp_CA = read_service_MAP("CA")
    results = {}
    count = 0
    for r,w in websites:
        if(count >= 1335):
            output = find_and_classify(w,ocsp_CA)
            results[(r,w)] = output
            if(count % 5 == 0):
                print(country,"ca",month,results)
                write_results("f{PARENT_DIR_PATH}/CAdep",country,"ca",month,results)
                results = {}
        count+=1
        

        

if __name__ == "__main__":
    import logging.config
    logging.config.fileConfig(f'{PARENT_DIR_PATH}/log.conf')
    main()