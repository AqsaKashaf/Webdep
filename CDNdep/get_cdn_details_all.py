import sys
from get_crux import *
from get_cdn_details_unit import *

from config import *



def main():
    # check if input given
    country = "us"
    # if(len(sys.argv) < 2):
    #     raise Exception("Please provide an output file path")
    
    output_file_path = f"{PARENT_DIR_PATH}/CDNdep" #sys.argv[1]
    start = int(sys.argv[1])
    end = int(sys.argv[2])
    if(len(sys.argv) > 1):
        country = sys.argv[1]
        if(not check_valid_country(country)):
            raise Exception("Please enter a valid country code, {country} is not valid")
    
    month = get_last_month()
    websites = extract_crux_file(country, month)
    CDN_MAP = read_service_MAP("CDN")
    results = {}
    count = 0
    for r,w in websites:
        if(count >= start and count < end):
            print(r,w)
            output, _ = find_and_classify(w, CDN_MAP)
            results[(r,w)] = output
            if(count % 5 == 0):
                print(country,"cdn",month,results)
                write_results_cdn(output_file_path,country,"cdn",month,results)
                results = {}
        count+=1
    


        

if __name__ == "__main__":
    import logging.config
    logging.config.fileConfig('../log.conf')
    main()