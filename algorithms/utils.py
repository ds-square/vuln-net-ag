"""
These functions checks the pre-post condition chaining
"""
def get_req_privilege(str_priv):
    if str_priv == "NONE" or str_priv == "LOW":
        return "guest"
    elif str_priv == "SINGLE" or str_priv == "MEDIUM":
        return "user"
    else:
        return "root"
def get_gain_privilege(isroot, isuser, req_privilege):
    if isroot == "UNCHANGED" and isuser == "UNCHANGED":
        return get_req_privilege(req_privilege)
    elif isroot == True:
        return "root"
    elif isuser == True:
        return "user"
    else:
        return "user"
def retrieve_privileges(vulnID,vulnerabilities):
    for vuln in vulnerabilities:
        if vuln["id"] == vulnID:
            if "cvssMetricV2" in vuln["metrics"]:
                metricV2 = vuln["metrics"]["cvssMetricV2"][0]
                metricCvssV2 = metricV2["cvssData"]
                
                priv_required = get_req_privilege(metricCvssV2["authentication"])
                priv_gained = get_gain_privilege(metricV2["obtainAllPrivilege"],metricV2["obtainUserPrivilege"],metricCvssV2["authentication"])
                return vuln,priv_required,priv_gained
            elif "cvssMetricV30" in vuln["metrics"] or "cvssMetricV31" in vuln["metrics"]: 
                if "cvssMetricV30" in vuln["metrics"]: metricV3 = vuln["metrics"]["cvssMetricV30"][0]
                else: metricV3 = vuln["metrics"]["cvssMetricV31"][0]
                metricCvssV3 = metricV3["cvssData"]

                priv_required = get_req_privilege(metricCvssV3["privilegesRequired"])
                priv_gained = get_gain_privilege(metricCvssV3["scope"],metricCvssV3["scope"],metricCvssV3["privilegesRequired"])
                return vuln,priv_required,priv_gained
            else:
                return vuln,"guest","guest"
            
"""
This function returns the list of vulnerability IDs, given a host
"""
def get_vulns_from_host(host):
    vuln_list = []
    for iface in host["network_interfaces"]:
        for port in iface["ports"]:
            for service in port["services"]:
                vuln_list+=service["cve_list"]
    return list(set(vuln_list))

"""
This function returns the list of cpes, given a host
"""
def get_cpes_from_host(host):
    cpe_list = []
    for iface in host["network_interfaces"]:
        for port in iface["ports"]:
            for service in port["services"]:
                cpe_list+=service["cpe_list"]
    return list(set(cpe_list))

"""
This function returns the credential that is requisite for the given vulnerability
"""
def get_credential_from_vuln(vuln):
    metric = vuln["metrics"]
    if "cvssMetricV2" in metric.keys():
        return metric["cvssMetricV2"][0]["cvssData"]["authentication"]
    elif "cvssMetricV30" in metric.keys():
        return metric["cvssMetricV30"][0]["cvssData"]["attackVector"]
    elif "cvssMetricV31" in metric.keys():
        return metric["cvssMetricV31"][0]["cvssData"]["attackVector"]
    else: return "SINGLE"
    