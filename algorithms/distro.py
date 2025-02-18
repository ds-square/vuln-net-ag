"""
DISTRIBUTED APPROACH
Abdulhakim Sabur, Ankur Chowdhary, Dijiang Huang, and Adel Alshamrani. 2022. 
Toward scalable graph-based security analysis for cloud networks. 
Computer Networks 206 (April 2022), 108795. 
https://doi.org/10.1016/j.comnet.2022.108795
"""

import json, logging, time, csv, random
import networkx as nx
import pandas as pd
from pebble import ProcessPool
import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

import warnings
warnings.filterwarnings("ignore")

import config
from algorithms.utils import retrieve_privileges, get_vulns_from_host

def build_model_graph(devices,vulnerabilities,reachability_edges,network_file=None):
    if network_file:
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
                    req_node = req+"@"+str(src_id)
                    gain_node = gain+"@"+str(dst_id)
                    vuln_node = vuln["id"]

                    if req_node not in G.nodes(): G.add_node(req_node, type="privilege", color="green")
                    if gain_node not in G.nodes(): G.add_node(gain_node, type="privilege", color="green")
                    if vuln_node not in G.nodes(): G.add_node(vuln_node, type="vulnerability", color="blue")
                    if (req_node, vuln_node) not in G.edges(): G.add_edge(req_node, vuln_node)
                    if (vuln_node, gain_node) not in G.edges(): G.add_edge(vuln_node, gain_node)
    return G
    # nx.write_graphml_lxml(G, config.GRAPH_FOLDER+"TVA_"+network_file.split(".json")[0]+".graphml")

from sklearn.cluster import KMeans
import math
def segment_establishment(devices,vulnerabilities):
    dic_cpe_segment = {}

    for dev in devices:
        for iface in dev["network_interfaces"]:
            for port in iface["ports"]:
                for serv in port["services"]:
                    # print(serv["cve_list"])
                    serv_vector=[0,0,0,0,0,0,0,0]
                    for cve in serv["cve_list"]:
                        for vuln in vulnerabilities:
                            classified=False
                            if vuln["id"] == cve:
                                for desc in vuln["descriptions"]:
                                    if desc["lang"] == "en":
                                        eng_desc = desc["value"]
                                        if "http" in eng_desc or "HTTP" in eng_desc or "web" in eng_desc: 
                                            serv_vector[0]+=1
                                            classified=True
                                        if "SQL" in eng_desc or "sql" in eng_desc or "storage" in eng_desc: 
                                            serv_vector[1]+=1
                                            classified=True
                                        if "file" in eng_desc or "FTTP" in eng_desc or "fttp" in eng_desc: 
                                            serv_vector[2]+=1
                                            classified=True
                                        if "time" in eng_desc or "clock" in eng_desc or "sync" in eng_desc: 
                                            serv_vector[3]+=1
                                            classified=True
                                        if "user" in eng_desc or "password" in eng_desc: 
                                            serv_vector[4]+=1
                                            classified=True
                                        if "mail" in eng_desc or "MAIL" in eng_desc or "smtp" in eng_desc: 
                                            serv_vector[5]+=1
                                            classified=True
                                        if "remote" in eng_desc or "rpc" in eng_desc or "rcp" in eng_desc or "execute" in eng_desc: 
                                            serv_vector[6]+=1
                                            classified=True
                                        if not classified:
                                            serv_vector[7]+=1
                            classified=False
                    dic_cpe_segment[dev["hostname"]] = serv_vector
    
    start = time.perf_counter()
    
    services=[]
    services_key=[]
    for k in dic_cpe_segment.keys():
        vect = dic_cpe_segment[k]
        services_key.append(k)
        max_v = max(vect)/8
        if max_v<=0: max_v=1
        services.append([math.ceil(x//max_v) for x in vect])
    
    mu_1 = [4,1,5,6,2,7,3,8]
    mu_2 = [4,2,5,6,1,7,3,8]
    mu_3 = [4,3,5,6,2,7,1,8]
    mu_4 = [1,2,3,4,5,6,7,8]
    mu_5 = [8,7,6,5,4,3,2,1]
    init_vect = [mu_1,mu_2,mu_3,mu_4,mu_5]

    # no_dup = [list(i) for i in set(map(tuple, services))]
    # n_clust=3
    # if len(no_dup)==1: n_clust=1
    # elif len(no_dup)==2: n_clust=2
    # else: n_clust=3
    
    X = services
    kmeans = KMeans(n_clusters=5, init=init_vect).fit(X)

    cluster1=[]
    cluster2=[]
    cluster3=[]
    for i in range(0,len(kmeans.labels_)):
        if kmeans.labels_[i]==0: cluster1.append(services_key[i])
        elif kmeans.labels_[i]==1: cluster2.append(services_key[i])
        else: cluster3.append(services_key[i])
    
    end = time.perf_counter()
    return end-start,{"c1":cluster1,"c2":cluster2,"c3":cluster3}

def compute_subAG(all_dev,all_vuln,all_edge,hostname_list):
    cluster_dev=[]
    cluster_edges=[]
    for dev in all_dev:
        if dev["hostname"] in hostname_list: cluster_dev.append(dev)
        for edge in all_edge:
            if dev["hostname"] in edge["host_link"]: cluster_edges.append(edge)
    start=time.perf_counter()
    subG = build_model_graph(cluster_dev,all_vuln,cluster_edges)
    end=time.perf_counter()

    return end-start, subG

def is_connected(g1,g2,edges):
    edges_connecting=[]
    for n1 in g1:
        for n2 in g2:
            for edge in edges:
                if edge["host_link"][0] == n1 and edge["host_link"][1] == n2:
                    edges_connecting.append([n1,n2])
    return edges_connecting
    
def merge(graph_lists):
    to_merge = graph_lists
    while len(to_merge)>2:
        for G1,G2 in zip(to_merge[0::2], to_merge[1::2]):
            R = nx.compose(G1, G2)
            to_merge.remove(G1)
            to_merge.remove(G2)
            to_merge.append(R)
            
    R = nx.compose(to_merge[0], to_merge[1])
    return R

def distro_generation(params):
    net_file, ag_file, G, S_init, S_goal, generate_paths = params
    logging.basicConfig(filename=config.LOG_FOLDER+'distro.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')
    
    # df = pd.read_csv(config.STATS_FOLDER+config.generation_stats_file) #TODO
    # mod,nhost,nvuln,topo,distro,diver = ag_file.split(".graphml")[0].split("_") #TODO
    # num_sources = len(S_init)
    # num_targets = len(S_goal)
    # df_exist = df.loc[(df['model']==mod) & 
    #          (df['num_host']==nhost) & 
    #          (df['num_vuln']==nvuln) &
    #          (df['topology']==topo) &
    #          (df['distro_vuln']==distro) &
    #          (df['diversity_vuln']==diver) &
    #          (df['num_entries']==num_sources)&
    #          (df['num_targets']==num_targets)]
    # if len(df_exist)>0: 
    #     logging.debug("Already generated experiment: %s", ag_file)
    #     print(ag_file)
    #     return 0

    logging.info("Starting DISTRO generation: %s", ag_file)

    with open(net_file) as nf:
        content_network = json.load(nf)
    all_devices = content_network["devices"]
    all_vulnerabilities=content_network["vulnerabilities"]
    all_edges=content_network["edges"]

    # serialG=build_model_graph(all_devices,all_vulnerabilities,all_edges)
    G=nx.DiGraph()

    try:
        time_segment, clusters_dic = segment_establishment(all_devices,all_vulnerabilities)
        
        cluster_hosts = []
        sub_graphs=[]
        times_subAG=[]
        for cluster in clusters_dic.values():
            start_cl=time.perf_counter()
            time_curr, sub_clusterAG = compute_subAG(all_devices,all_vulnerabilities,all_edges,cluster)
            sub_graphs.append(sub_clusterAG)
            if len(cluster)>0: cluster_hosts.append(cluster)
            end_cl=time.perf_counter()
            times_subAG.append(time_curr)
        
        time_generation = max(times_subAG)
        
        logging.info("%s num cluster: %d", ag_file, len(cluster_hosts))
        time_merges=[]
        if len(cluster_hosts)<=1:
            G = sub_graphs[0]
            time_merges.append(0)
        else:
            for i in range(0,len(cluster_hosts)):
                for j in range(0,len(cluster_hosts)):
                    if i!=j:
                        check_connection = is_connected(cluster_hosts[i],cluster_hosts[j],all_edges)
                        if len(check_connection)>0:
                            inter_seg_hosts = list(set([x for xs in check_connection for x in xs]))
                            time_merge,connAG = compute_subAG(all_devices,all_vulnerabilities,all_edges,inter_seg_hosts)
                            start_compose=time.perf_counter()
                            R1=nx.compose(sub_graphs[i], connAG)
                            R2=nx.compose(sub_graphs[j], connAG)
                            R=nx.compose(R1, R2)
                            G=nx.compose(G,R)
                            end_compose=time.perf_counter()
                            time_merges.append(time_merge+(end_compose-start_compose))
                        else:
                            time_merges.append(0)
        
        time_merging = max(time_merges)

        tot_time = time_segment+time_generation+time_merging
        # logging.info("%s should be: %d, is: %d", ag_file, len(serialG.edges), len(G.edges))

    #     # attack_paths = []
    #     # if generate_paths:
    #     #    for source in S_init:
    #     #        for dest in S_goal:
    #     #             print(source,dest)
    #     #             for path in nx.all_simple_paths(G_filtered,source,dest):
    #     #                 attack_paths.append(path)
        
    #     end = time.perf_counter()
        if len(times_subAG)<=0: times_subAG.append(0)
        if len(time_merges)<=0: time_merges.append(0)
        ag_file = ag_file.replace(".graphml","").replace("TVA","DISTRO")
        with open(config.STATS_FOLDER+config.distro_stats,'a',newline='') as fd:
            params_network_ag = ag_file.split(".json")[0].split("_")+[tot_time,
                    sum(times_subAG)/len(times_subAG),min(times_subAG),max(times_subAG),
                    sum(time_merges)/len(time_merges),min(time_merges),max(time_merges),
                    time_segment,len(cluster_hosts)]
            writer = csv.writer(fd)
            writer.writerow(params_network_ag)
        logging.info("WRITTEN DISTRO generation: %s", ag_file)
    
    except Exception as e:
        print(e)
        logging.error("[ERROR] %s on file %s", e, ag_file)
        # with open(config.STATS_FOLDER+config.generation_stats_file,'a',newline='') as fd:
        #     params_network_ag = ag_file.split(".graphml")[0].split("_")+[num_sources,num_targets,num_paths,generation_time,generate_paths]
        #     writer = csv.writer(fd)
        #     writer.writerow(params_network_ag)
    
    # logging.info("WRITTEN TVA generation: %s", ag_file)
    # return len(attack_paths)

if __name__ == "__main__":
    logging.basicConfig(filename=config.LOG_FOLDER+'distro.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')
    config.create_distro_stats_file()
    model = "TVA"
    generate_path = config.generate_all_paths

    df_made = pd.read_csv(config.STATS_FOLDER+config.distro_stats)
    # Create an empty list
    processed_graphs =[]
    for index, rows in df_made.iterrows():
        str_file= "TVA_"+str(rows.num_host)+"_"+str(rows.num_vuln)+"_"+rows.topology+"_"+rows.distro_vuln+"_"+\
            str(rows.diversity_vuln).replace(".0","")+".graphml"
        processed_graphs.append(str_file)

    parameters = []
    for ag_file in os.listdir(config.GRAPH_FOLDER):
        if model not in ag_file: continue
        if ag_file in processed_graphs: continue
        net_filename = ag_file.replace("TVA_","").replace("graphml","json") 
        net_file = config.NETWORK_FOLDER+net_filename
        # ag_file = net_file.replace("networks/","").replace("json","graphml")
        # if model+"_"+ag_file not in os.listdir(config.GRAPH_FOLDER): 
        #     logging.info("File %s not in folder", model+"_"+ag_file)
        #     continue
        for nh in config.nhosts:
            for nv in config.nvulns:
                for t in config.topologies:
                    for d in config.distro:
                        for dd in config.diversity:
                            if str(nh)+"_"+str(nv)+"_"+t+"_"+d+"_"+str(dd) in net_file:
                                G = nx.read_graphml(config.GRAPH_FOLDER+ag_file)
                                parameters.append([net_file,ag_file,G,[],[],generate_path])
                                logging.info("Added graph %s to queue", ag_file)

        
        # G = nx.read_graphml(config.GRAPH_FOLDER+ag_file)
        # parameters.append([net_file,ag_file,G,[],[],generate_path])
        # logging.info("Added graph %s to queue", ag_file)
        # if batch>=50: break
        # batch+=1
        # # try:
        # #     G = nx.read_graphml(config.GRAPH_FOLDER+model+"_"+ag_file)
        # #     state_nodes=[]
        # #     for n in G.nodes():
        # #         if "CVE" not in n:state_nodes.append(n)

        # #     for num_src in config.num_entry_points:
        # #         if num_src > len(state_nodes): num_s = len(state_nodes)-1
        # #         else: num_s = num_src
        # #         for num_trg in config.num_entry_points:
        # #             if num_trg > len(state_nodes): num_t = len(state_nodes)-1
        # #             else: num_t = num_trg
                    
        # #             S_init = random.sample(list(state_nodes),num_s)
        # #             S_goal = random.sample(list(state_nodes),num_t)
        # #             # for n in G.nodes():
        # #             #     if n not in S_init: S_goal.append(n)
        # #             #     if len(S_goal) == num_t: break
        # #             parameters.append([net_file,ag_file,G,S_init,S_goal,generate_path])
            
            
        # # except Exception as e:
        # #     logging.error("%s", e)
        # #     logging.error("File NOT writter: %s", ag_file)

    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(distro_generation, parameters)#, timeout=config.timeout)