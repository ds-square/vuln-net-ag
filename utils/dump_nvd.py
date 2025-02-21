import requests, time, json, os, logging, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import config

logger = logging.getLogger(__name__)
logfile = 'logging/dump.log'
URL_CPE = "https://services.nvd.nist.gov/rest/json/cpes/2.0?"
URL_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0?"

def cpe_dump(cpe_file, key=config.nvd_key):
    if key: headers = {'content-type': 'application/json', 'apiKey': key}
    else: headers = {'content-type': 'application/json'}
    
    pull_srv=[]
    for serv in config.OS+config.SERVICES:
        logger.info(f"Retrieving CPE for {serv}")
        
        startIndex=0
        totalResults=1
        while(True):
            if startIndex >= totalResults: break
            for attempt in range(1,5):
                params={
                    "keywordSearch": serv,
                    "startIndex": startIndex,
                    "resultsPerPage": 2000
                }
                time.sleep(3)
                response = requests.get(URL_CPE, params=params,  headers=headers)
                
                if response.status_code == 200:
                    jsonResponse = response.json()
                    totalResults = jsonResponse["totalResults"]
                    startIndex+=jsonResponse["resultsPerPage"]
                    
                    for cpe in jsonResponse["products"]:
                        cpeObj = cpe["cpe"]
                        if cpeObj["deprecated"] != True:
                            pull_srv.append(cpeObj)
                    
                    logger.info(f"Found {startIndex} for {serv} (Total: {totalResults})")
                    break
                else:
                    logger.error(f"Error retrieving CPE records: {response.status_code} --- Retry temptative: {attempt}")
                    time.sleep(6+attempt)
                    if attempt<=5: continue
                    else: break
            
    with open(cpe_file, "w") as outfile:
        json_data = json.dumps({"services":pull_srv},
                                default=lambda o: o.__dict__, indent=2)
        outfile.write(json_data)
    
    logger.info(f"Service file {cpe_file} written")
    return len(pull_srv)

def cve_dump(cpe_file, cve_file, key=config.nvd_key):
    if key: headers = {'content-type': 'application/json', 'apiKey': key}
    else: headers = {'content-type': 'application/json'}
    
    with open(cpe_file) as cpe_f:
        services = json.load(cpe_f)["services"]
    
    pull_vulns=[]
    for cpe in services:        
        cpeName = cpe["cpeName"]
        logger.info(f"Retrieving CVE for {cpeName}")
        
        startIndex=0
        totalResults=1
        while(True):
            if startIndex >= totalResults: break
            for attempt in range(1,5):
                params={
                    "cpeName": cpeName,
                    "startIndex": startIndex,
                    "resultsPerPage": 2000
                }
                time.sleep(3)
                response = requests.get(URL_CVE, params=params,  headers=headers)
                
                if response.status_code == 200:
                    jsonResponse = response.json()
                    totalResults = jsonResponse["totalResults"]
                    startIndex+=jsonResponse["resultsPerPage"]
                    
                    for cve in jsonResponse["vulnerabilities"]:
                        cveObj = cve["cve"]
                        cveObj["cpe"] = cpeName
                        pull_vulns.append(cveObj)
                    
                    logger.info(f"Found {startIndex} for {cpeName} (Total: {totalResults})")
                    break
                else:
                    logger.error(f"Error retrieving CVE records: {response.status_code} --- Retry temptative: {attempt}")
                    time.sleep(6+attempt)
                    if attempt<=5: continue
                    else: break
    
    with open(cve_file, "w") as outfile:
        json_data = json.dumps({"vulnerabilities":pull_vulns},
                                default=lambda o: o.__dict__, indent=2)
        outfile.write(json_data)
    
    logger.info(f"Vulnerability file {cve_file} written")
    return len(pull_vulns)


def get_pool_vulnerabilities(tot_vulns):
    with open(config.cve_dump_file) as cve_f:
        vulnerabilities = json.load(cve_f)["vulnerabilities"]
    
    win_os = []
    linux_os = []
    srv=[]
    for vuln in vulnerabilities:
        if "windows" in vuln["cpe"]: win_os.append(vuln)
        elif "ubuntu" in vuln["cpe"] or "debian" in vuln["cpe"]: linux_os.append(vuln)
        else: srv.append(vuln)
    
    win = win_os+srv
    lin = linux_os+srv
    return win[0:tot_vulns], lin[0:tot_vulns]

def dump():
    logging.basicConfig(filename=logfile, level=logging.INFO, filemode='w', format='%(asctime)s - %(levelname)s: %(message)s')
    
    if not os.path.exists(config.NVD_DUMP_FOLDER): os.makedirs(config.NVD_DUMP_FOLDER)
    print(f"Starting CPE dump: see {logfile} for more information")
    tot_cpes = cpe_dump(config.cpe_dump_file)
    print(f"Found {tot_cpes} CPEs")
    
    print(f"Starting CVE dump: see {config.cve_dump_file} for more information")
    tot_cves = cve_dump(config.cpe_dump_file, config.cve_dump_file)
    print(f"Found {tot_cves} CVEs")