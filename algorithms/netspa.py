"""
NetSPA
model: privilege_required -> prerequisite(credential) -> vulnerability -> privilege_gained
"""
import json, csv, time, logging
from pebble import ProcessPool
import networkx as nx
import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

import config
from algorithms.utils import retrieve_privileges, get_vulns_from_host, get_credential_from_vuln

"""
This function create the AG models according to NetSPA and store it in a 
graphml file
"""
def build_model_graph(network_file):
    with open(config.NETWORK_FOLDER+network_file) as nf:
        content_network = json.load(nf)
    reachability_edges = content_network["edges"]
    devices = content_network["devices"]
    vulnerabilities = content_network["vulnerabilities"]

    G = nx.DiGraph()
    for r_edge in reachability_edges:
        src_id = r_edge["host_link"][0]
        dst_id = r_edge["host_link"][1]
        for host in devices:
            if host["hostname"] == dst_id:
                dst_vulns = get_vulns_from_host(host)
                for v in dst_vulns:
                    vuln,req,gain = retrieve_privileges(v,vulnerabilities)
                    req_state_node = req+"@"+str(src_id)
                    gain_state_node = gain+"@"+str(dst_id)
                    prerequisite_node = get_credential_from_vuln(vuln)
                    vuln_node = vuln["id"]
                    
                    if req_state_node not in G.nodes(): G.add_node(req_state_node, type="state", color="green")
                    if gain_state_node not in G.nodes(): G.add_node(gain_state_node, type="state", color="green")
                    if prerequisite_node not in G.nodes(): G.add_node(prerequisite_node, type="prerequisite", color="red")
                    if vuln_node not in G.nodes(): G.add_node(vuln_node, type="vulnerability", color="blue")

                    if (req_state_node, prerequisite_node) not in G.edges(): G.add_edge(req_state_node, prerequisite_node)
                    if (prerequisite_node, vuln_node) not in G.edges(): G.add_edge(prerequisite_node, vuln_node)
                    if (vuln_node, gain_state_node) not in G.edges(): G.add_edge(vuln_node, gain_state_node)
    nx.write_graphml_lxml(G, config.GRAPH_FOLDER+"NETSPA_"+network_file.split(".json")[0]+".graphml")


def create_data_structures(G):
    S2C = {}
    C2V = {}
    V2S = {}
    types_node = nx.get_node_attributes(G,"type")
    for edge in G.edges():
        src = edge[0]
        dst = edge[1]
        if types_node[src] == "state":
            if src in S2C.keys(): S2C[src].append(dst)
            else: S2C[src] = [dst]
        elif types_node[src] == "prerequisite":
            if src in C2V.keys(): C2V[src].append(dst)
            else: C2V[src] = [dst]
        else:
            if src in V2S.keys(): V2S[src].append(dst)
            else: V2S[src] = [dst]
    return S2C,C2V,V2S

def main_loop(params):
    logging.basicConfig(filename='logging/netspa.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')

    ag_file, AG_model, BFSQueue, generate_paths = params
    
    logging.info("Starting NETSPA generation: %s", ag_file)
    start = time.perf_counter()
    S2C,C2V,V2S = create_data_structures(AG_model)

    types_node = nx.get_node_attributes(AG_model,"type")
    attack_paths = []
    attack_steps = []
    brand_old = []
    starting_nodes = [] 
    for elem in BFSQueue: starting_nodes.append(elem)

    while len(BFSQueue)!=0:
        currNode = BFSQueue.pop(0)
        brand_old.append(currNode)
        if types_node[currNode] == "state" and currNode in S2C.keys():
            dest_set = S2C[currNode]
        elif types_node[currNode] == "prerequisite" and currNode in C2V.keys():
            dest_set = C2V[currNode]
        elif types_node[currNode] == "vulnerability" and currNode in V2S.keys():
            dest_set = V2S[currNode]
        else: dest_set = []

        if currNode in starting_nodes: 
            for destNode in dest_set: 
                attack_paths.append([currNode,destNode])
                if destNode not in brand_old:
                        BFSQueue.append(destNode)
        else:
            for destNode in dest_set:
                if generate_paths:
                    for p in attack_paths:
                        if p[len(p)-1] == currNode:
                            p_cpy = p.copy()
                            p_cpy.append(destNode)
                            attack_paths.append(p_cpy)
                else:
                    attack_steps.append([currNode,destNode])
                if destNode not in brand_old:
                    BFSQueue.append(destNode)    
    end = time.perf_counter()

    num_paths = len(attack_paths) if generate_paths else len(attack_steps)
    num_sources = len(starting_nodes)
    generation_time = end-start
    with open(config.STATS_FOLDER+config.generation_stats_file,'a',newline='') as fd:
        params_network_ag = ag_file.split(".graphml")[0].split("_")+[num_sources,len(AG_model.nodes()),num_paths,generation_time,generate_paths]
        writer = csv.writer(fd)
        writer.writerow(params_network_ag)
    logging.info("WRITTEN NETSPA generation: %s", ag_file)


if __name__ == "__main__":
    logging.basicConfig(filename='logging/netspa.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')
    config.create_generation_stats_file(False)
    model = "NETSPA"
    generate_path = config.generate_all_paths

    parameters = []
    for ag_file in os.listdir(config.GRAPH_FOLDER):
        if model in ag_file:
            graph_file = config.GRAPH_FOLDER+ag_file
            try:
                G = nx.read_graphml(graph_file)
                for num_src in config.num_entry_points+[len(G.nodes())-1]:
                    if num_src > len(G.nodes()): num_s = len(G.nodes())-1
                    else: num_s = num_src

                    BFSQueue_start = list(G.nodes())[0:num_s]
                    parameters.append([ag_file,G,BFSQueue_start, generate_path])
                
            except Exception as e:
                logging.error("%s", e)
                logging.error("File NOT writter: %s", ag_file)

    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(main_loop, parameters, timeout=config.timeout)