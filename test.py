import requests
import json
import config

def search_cpe(keyword):
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=Red Hat"
    params = {
        "resultsPerPage": 10
    }
    
    response = requests.get(url)
    print(response)
    
    if response.status_code == 200:
        data = response.json()
        if "result" in data and "cpes" in data["result"]:
            for cpe in data["result"]["cpes"]:
                print(cpe)
        else:
            print("No CPEs found.")
    else:
        print(f"Error: {response.status_code}")

if __name__ == "__main__":
    search_cpe("MySQL")