"""
MulVAL (input files)

attackerLocated(src_host).
attackerGoal(execCode(host,user)).

hacl(host_src,host_dst,_,_).

networkServiceInfo(host,'cpe',TCP,80,privilegeEscalation)

vulExists(host, CVE, 'cpe').
vulProperty(CVE, accessVector, privilegeEscalation).
"""
import json, os, csv
import networkx as nx
import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

import utils
import config

def write_mulval_inputs(network_file):
    with open(network_file) as f:
        content = json.load(f)
    devices = content["devices"]
    vulnerabilities = content["vulnerabilities"]
    reachability_edges = content["edges"]

    rules = []
    hosts_ids = [o["hostname"] for o in devices]

    rules.append("attackerLocated(h"+str(hosts_ids[0])+").")
    rules.append("attackGoal(execCode(h"+str(hosts_ids[len(hosts_ids)-1])+",_)).")

    for edge in reachability_edges:
        src = edge["host_link"][0]
        dst = edge["host_link"][1]
        rule_hcl = "hacl(h"+str(src)+",h"+str(dst)+",_,_)."
        rules.append(rule_hcl)
        
    for dev in devices:
        host_id = dev["hostname"]
        vulns = utils.get_vulns_from_host(dev)
        for v in vulns:
            # cpe = random.choice(utils.get_cpes_from_host(dev))
            rule_vulexist = "vulExists(h"+str(host_id)+",'"+v+"',_)."
            rules.append(rule_vulexist)
            vuln_full, pre, post = utils.retrieve_privileges(v,vulnerabilities)
            rule_network_info = "networkServiceInfo(h"+str(host_id)+",_,_,_,"+pre+")."
            rules.append(rule_network_info)

    for cve in vulnerabilities:
        vuln_id = cve["id"]
        if "cvssMetricV2" in cve["metrics"]:
            metricV2 = cve["metrics"]["cvssMetricV2"][0]
            metricCvssV2 = metricV2["cvssData"]
            acVector = metricCvssV2["accessVector"]
            post = utils.get_gain_privilege(metricV2["obtainAllPrivilege"],metricV2["obtainUserPrivilege"],metricCvssV2["authentication"])
        elif "cvssMetricV30" in cve["metrics"]:
            metricV3 = cve["metrics"]["cvssMetricV30"][0]
            metricCvssV3 = metricV3["cvssData"]
            acVector = metricCvssV3["attackVector"]
            post = utils.get_gain_privilege(metricCvssV3["scope"],metricCvssV3["scope"],metricCvssV3["privilegesRequired"])
        elif "cvssMetricV31" in cve["metrics"]:
            metricV3 = cve["metrics"]["cvssMetricV31"][0]
            metricCvssV3 = metricV3["cvssData"]
            acVector = metricCvssV3["attackVector"]
            post = utils.get_gain_privilege(metricCvssV3["scope"],metricCvssV3["scope"],metricCvssV3["privilegesRequired"])
        else:
            acVector = "NETWORK"
            post = "user"
        if acVector == "NETWORK": exploit = "remoteExploit"
        else: exploit = "localExploit"
        rule_vulprop = "vulProperty('"+vuln_id+"',"+exploit+",privEscalation)."
        rules.append(rule_vulprop)
    
    with open(config.MULVAL_IN_FOLDER+network_file.split("/")[1].replace(".json",".P"), "w") as mulval_f:
        for rule in rules:
            mulval_f.write(rule)
            mulval_f.write('\n')

def build_model(mulv_input):
    G = nx.DiGraph()
    if not os.path.exists(mulv_input+"-ARCS.CSV") or not os.path.exists(mulv_input+"-VERTICES.CSV"): return
    with open(mulv_input+"-ARCS.CSV") as edges_file, open(mulv_input+"-VERTICES.CSV") as nodes_file:
        for node in nodes_file.readlines():
            params = node.split(",")
            node_id = params[0]
            if "RULE" in params[1]: node_type = "derivation"
            else: node_type = "fact"
            node_rule = params[1]
            G.add_node(node_id, type=node_type, value=node_rule)
        for edge in edges_file.readlines():
            param_e = edge.split(",")
            src=param_e[0]
            dst=param_e[1]
            G.add_edge(src, dst)
    nx.write_graphml_lxml(G, config.GRAPH_FOLDER+"MULVAL_"+mulv_input.split("/")[1].split(".P")[0]+".graphml")

def stats_mulval_time():
    isDataset=False
    isTime=False
    with open(config.mulval_time_file) as f:
        for line in f.readlines():
            if "dataset" in line: 
                current_setting = line.split("/")[1].split(".P")[0]
                isDataset = True
            if "real" in line: 
                time_string = line.replace(" ","").replace("\t","").split("real")[1]
                # if "h" in time_string: hours = time_string.split("h")[0]
                minutes = float(time_string.split("m")[0])
                seconds = float(time_string.split("m")[1].split("s")[0])
                isTime = True
            if isDataset and isTime:
                isDataset=False
                isTime=False
                with open(config.STATS_FOLDER+config.graph_stats_file,'a',newline='') as fd:
                    params_network_ag = ["MULVAL"]+current_setting.split("_")+[minutes*60+seconds]
                    writer = csv.writer(fd)
                    writer.writerow(params_network_ag)

if __name__ == "__main__":
    
    """
    Generate input files according to MULVAL notation
    """
    if not os.path.exists(config.MULVAL_IN_FOLDER): os.makedirs(config.MULVAL_IN_FOLDER)
    for ag_file in os.listdir(config.NETWORK_FOLDER):
        if config.MULVAL_IN_FOLDER+ag_file.replace(".json",".P") not in os.listdir(config.MULVAL_IN_FOLDER):
            params = ag_file.split("_")
            write_mulval_inputs(config.NETWORK_FOLDER+ag_file)                    
    
    ### Uncomment this part after running MulVAL tool with generated .P files (https://people.cs.ksu.edu/~xou/mulval/)
    
    # """
    # Parse MULVAL time statistics
    # """
    # stats_mulval_time()
    #
    # """
    # Parse MULVAL output files to generate attack graphs
    # """
    # computed_file=[]
    # for filename in os.listdir(config.MULVAL_OUT_FOLDER):
    #     network_setting = filename.split("-")[0]
    #     if "ARCS" in filename and network_setting not in computed_file: 
    #         build_model(config.MULVAL_OUT_FOLDER+network_setting)
    #         computed_file.append(network_setting)