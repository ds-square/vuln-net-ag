import json, random, uuid
import numpy as np
import networkx as nx

from utils.dump_nvd import get_pool_vulnerabilities
import models.NetworkModel as net

def build_lan_topology(percentage_link,N):
    
    isLan2 = True if len(N)>10 else False
    
    if len(N)<=4:
        node_lan = len(N)
        return nx.complete_graph(N, nx.DiGraph())
    elif len(N)>4 and len(N)<=8:
        node_lan = len(N)
        DMZ = nx.complete_graph(N[0:2], nx.DiGraph())
        ALAN = nx.complete_graph(N[2:4], nx.DiGraph())
        LAN1 = nx.complete_graph(N[4:len(N)], nx.DiGraph())
    elif len(N)>8 and len(N)<=10:
        node_lan = len(N)
        DMZ = nx.complete_graph(N[0:3], nx.DiGraph())
        ALAN = nx.complete_graph(N[3:6], nx.DiGraph())
        LAN1 = nx.complete_graph(N[6:len(N)], nx.DiGraph())
    else:
        node_lan = round(len(N)/4)
        DMZ = nx.complete_graph(N[0:node_lan], nx.DiGraph())
        ALAN = nx.complete_graph(N[node_lan:2*node_lan], nx.DiGraph())
        LAN1 = nx.complete_graph(N[2*node_lan:3*node_lan], nx.DiGraph())
        LAN2 = nx.complete_graph(N[3*node_lan:len(N)], nx.DiGraph())
    
    edges=[]
    for dmz_nodes in DMZ.nodes:
        for alan_nodes in ALAN.nodes:
            edges.append((alan_nodes,dmz_nodes))
            edges.append((dmz_nodes,alan_nodes))    
    
    max_edges = percentage_link*node_lan*node_lan
    count_lan1 = 0
    for alan_nodes in ALAN.nodes:
        for lan1_node in LAN1.nodes:
            if isLan2 and not count_lan1 >= max_edges:
                edges.append((alan_nodes,lan1_node))
                edges.append((lan1_node,alan_nodes))
                count_lan1+=1
            else:
                edges.append((alan_nodes,lan1_node))
                edges.append((lan1_node,alan_nodes))
    if isLan2:
        edges+=LAN2.edges
        count_lan2 = 0
        for alan_nodes in ALAN.nodes:
            for lan2_node in LAN2.nodes:
                if not count_lan2 >= max_edges:
                    edges.append((alan_nodes,lan2_node))
                    edges.append((lan2_node,alan_nodes))
                    count_lan2+=1
    
    edges+=DMZ.edges
    edges+=ALAN.edges
    edges+=LAN1.edges
    G = nx.DiGraph()
    G.add_edges_from(edges)
    return G

"""
Generate different network topology using networkx
"""
def build_topology(topology,nodes):
    if topology == 'mesh': G = nx.complete_graph(list(range(0,len(nodes))), nx.DiGraph())
    elif topology == 'random': G = nx.gnp_random_graph(len(nodes),0.5)
    elif topology == 'star': G = nx.star_graph(list(range(0,len(nodes))))
    elif topology == 'ring': G = nx.cycle_graph(list(range(0,len(nodes))), nx.DiGraph())
    elif topology == 'tree': G = nx.random_tree(len(nodes))
    elif topology == 'powerlaw': G = nx.powerlaw_cluster_graph(len(nodes),round(len(nodes)/2),0.5)
    elif 'lan' in topology:
        if '0' in topology: G = build_lan_topology(0,list(range(0,len(nodes))))
        elif '25' in topology: G = build_lan_topology(0.25,list(range(0,len(nodes))))
        else: G = build_lan_topology(0.5,list(range(0,len(nodes))))
    # nx.write_graphml_lxml(G, topology+".graphml")
    return G

"""
Generate vulnerabilities distribution using numpy
"""
def build_distribution(distro, num_nodes, num_vulns,nodes_list):
    tot_vuln = num_nodes*num_vulns

    if distro == "bernoulli":
        samples1 = list(np.random.binomial(num_vulns, 0.8, size=round(num_nodes/2)))
        samples2 = list(np.random.binomial(num_vulns, 0.2, size=round(num_nodes/2)))
        samples = samples1+samples2
        vulns_distro = {}
        # i=1
        for i in nodes_list:
            for s in samples:
                vulns_distro[i] = round(s/sum(samples)*tot_vuln)
                # i+=1
        return vulns_distro

    elif distro == "binomial":
        samples = list(np.random.binomial(num_vulns, 0.5, size=num_nodes))
        vulns_distro = {}
        # i=1
        for i in nodes_list:
            for s in samples:
                vulns_distro[i] = round(s/sum(samples)*tot_vuln)
                # i+=1
        return vulns_distro
    
    elif distro == 'poisson':
        samples = list(np.random.poisson(num_vulns, size=num_nodes))
        vulns_distro = {}
        # i=1
        for i in nodes_list:
            for s in samples:
                vulns_distro[i] = round(s/sum(samples)*tot_vuln)
                # i+=1
        return vulns_distro
    
    else: 
        vulns_distro = {}
        # for i in range(1,num_nodes+1): vulns_distro[i] = num_vulns
        for i in nodes_list: vulns_distro[i] = num_vulns
        return vulns_distro


"""
Assign vulnerabilities per host considering diversity distribution
"""
def build_diversity(vulns_per_host,percentage_div,vulnerabilities):
    max_vulns = max(vulns_per_host.values())
    tot_vulns = sum(vulns_per_host.values())
    full_pool_win, full_pool_lin = get_pool_vulnerabilities(tot_vulns,vulnerabilities)

    vuln_inventory = []
    dict_vuln_host = {}
    if percentage_div == 0:
        equal_pool = full_pool_win[0:max_vulns]
        for k in vulns_per_host.keys():
            n_vuln = vulns_per_host[k]
            vulnerabilities = equal_pool[0:n_vuln]
            vuln_inventory+=vulnerabilities
            dict_vuln_host[k] = [o["id"] for o in vulnerabilities]

    elif percentage_div == 1:
        diverse_pool_w = full_pool_win[0:tot_vulns]
        diverse_pool_l = full_pool_lin[0:tot_vulns]
        last_index = 0
        for k in vulns_per_host.keys():
            if k%2==0: diverse_pool=diverse_pool_w
            else: diverse_pool=diverse_pool_l
            
            n_vuln = vulns_per_host[k]
            vulnerabilities = diverse_pool[last_index:last_index+n_vuln]
            vuln_inventory+=vulnerabilities
            dict_vuln_host[k] = [o["id"] for o in vulnerabilities]
            last_index+=n_vuln

    else:
        split_index = round(max_vulns*(1-percentage_div))+1
        equal_pool = full_pool_win[0:split_index]
        diverse_pool_w = full_pool_win[split_index+1:]
        diverse_pool_l = full_pool_lin[split_index+1:]
        last_index = 0
        for k in vulns_per_host.keys():
            if k%2==0: diverse_pool=diverse_pool_w
            else: diverse_pool=diverse_pool_l
            
            n_vuln = vulns_per_host[k]
            sub_split_equal = round(n_vuln*(1-percentage_div))
            sub_split_diverse = round(n_vuln*percentage_div)
            
            vulns_equal = equal_pool[0:sub_split_equal]
            vulns_diverse = diverse_pool[last_index:last_index+sub_split_diverse]
            vulnerabilities = vulns_equal+vulns_diverse
            vuln_inventory+=vulnerabilities
            dict_vuln_host[k] = [o["id"] for o in vulnerabilities]
            last_index+=sub_split_diverse

    no_duplicate_ids = []
    no_duplicate_inventory = []
    for vuln in vuln_inventory:
        if vuln["id"] not in no_duplicate_ids:
            no_duplicate_inventory.append(vuln)
            no_duplicate_ids.append(vuln["id"])

    return no_duplicate_inventory,dict_vuln_host

def randomMAC():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255))

def write_reachability(base_folder,filename,vulnerabilities):
    params = filename.split(".json")[0].split("_")
    nhost=int(params[0])
    nvuln=int(params[1])
    topology=params[2]
    distro=params[3]
    diversity=float(params[4])

    nodes = list(range(1,nhost+1))
    G = build_topology(topology,nodes)
    edges=[]
    for edge in G.edges():
        if {"host_link": [edge[0],edge[1]]} not in edges: edges.append({"host_link": [edge[0],edge[1]]})
        if {"host_link": [edge[1],edge[0]]} not in edges: edges.append({"host_link": [edge[1],edge[0]]})
    # nx.write_graphml(G,"networks_graph/"+filename+".graphml")

    vulns_per_node = build_distribution(distro,nhost,nvuln,G.nodes)
    vuln_inventory, vulns_by_host = build_diversity(vulns_per_node,diversity,vulnerabilities)
    devices = []
    for k in vulns_by_host:
        for vuln in vuln_inventory:
            cpes_k = []
            if 'cpe' in vuln.keys():
                cpes_k.append(vuln['cpe'])
        service_k = net.Service("Workstation "+str(k), cpes_k, vulns_by_host[k])
        port_k = net.Port(8080, "open", "TCP", [service_k])
        devices.append({
            "id": str(uuid.uuid4()),
            "hostname": k,
            "type": "workstation",
            "network_interfaces": [net.NetworkInterface("75.62.132."+str(60+k),randomMAC(),[port_k])]
        })
    
    with open(base_folder+filename, "w") as outfile:
        json_data = json.dumps({"devices":devices,
                                "vulnerabilities":vuln_inventory,"edges":edges},
                                default=lambda o: o.__dict__, indent=2)
        outfile.write(json_data)