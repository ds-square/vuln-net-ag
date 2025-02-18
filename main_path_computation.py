import pandas as pd
import networkx as nx
import numpy as np
from pebble import ProcessPool
import os.path, sys, logging, time, csv
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

import config
import algorithms.netspa
import algorithms.tva

def pick_entry_points(graph_file):
    logging.basicConfig(filename='logging/paths.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')

    ag_graph = config.GRAPH_FOLDER+graph_file

    logging.info("[START] %s", graph_file)
    
    G = nx.read_graphml(ag_graph)
    all_paths_distances = {x[0]:x[1] for x in nx.all_pairs_shortest_path_length(G)}
    
    entry_points = {}
    for src in all_paths_distances.keys():
        dict_dist = all_paths_distances[src]
        max_val = max(dict_dist.values())
        dst = [k for k,v in dict_dist.items() if v >= max_val]
        for target in dst:
            entry_points[(src,target)]=max_val
    entry_points = dict(sorted(entry_points.items(), key=lambda x:x[1], reverse=True))

    combinations = []
    for i in config.num_entry_points:
        for j in config.num_entry_points:
            combinations.append([i,j])
    
    ### Check if experiment already performed
    df_path = pd.read_csv(config.path_stats_file)
    model,nhost,nvuln,topo,distro,diver = graph_file.replace(".graphml","").split("_")
    if diver == "1" or diver == "0": diver_cmp = int(diver)
    else: diver_cmp = float(diver)

    for setting in combinations:
        df = df_path[(df_path.model == model) & 
                    (df_path.num_host == int(nhost)) &
                    (df_path.num_vuln == int(nvuln)) &
                    (df_path.topology == topo) &
                    (df_path.distro_vuln == distro) &
                    (df_path.diversity_vuln == diver_cmp) &
                    (df_path.num_src == setting[0]) &
                    (df_path.num_target == setting[1])]
        if len(df)>0: 
            logging.debug("[ALREADY COMPUTED] %s (source:%d, target:%d)", graph_file, len(sources),len(goals))
            continue

        sources = []
        goals = []
        for entry in entry_points.keys():
            if len(sources) != setting[0]:
                sources.append(entry[0])
            if len(goals) != setting[1]:
                goals.append(entry[1])

        attack_paths = []
        lengths = []
        startTime = time.perf_counter()
        logging.info("[START %s] path generation started (source:%d, target:%d)", graph_file, len(sources),len(goals))
        for s in sources:
            for t in goals:
                all_paths = list(nx.all_simple_paths(G, source=s, target=t))
                for p in all_paths:
                    attack_paths.append(p)
                    lengths.append(len(p))
        endTime = time.perf_counter()
        logging.info("[END %s] path generation started (source:%d, target:%d)", graph_file, len(sources),len(goals))
        
        with open(config.path_stats_file, 'a', newline='') as fd:
            params_net = graph_file.replace(".graphml","").split("_")
            writer = csv.writer(fd)
            writer.writerow(params_net+[len(sources),len(goals),len(attack_paths),list(np.quantile(lengths,[0,0.25,0.5,0.75,1])),endTime-startTime])
    
    logging.info("[END] %s", graph_file)

def pruning(graph_file):
    logging.basicConfig(filename='logging/pruning_paths.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')

    ag_graph = config.GRAPH_FOLDER+graph_file

    logging.info("[START] %s", graph_file)
    
    G = nx.read_graphml(ag_graph)
    all_paths_distances = {x[0]:x[1] for x in nx.all_pairs_shortest_path_length(G)}
    
    entry_points = {}
    for src in all_paths_distances.keys():
        dict_dist = all_paths_distances[src]
        max_val = max(dict_dist.values())
        dst = [k for k,v in dict_dist.items() if v >= max_val]
        for target in dst:
            entry_points[(src,target)]=max_val
    entry_points = dict(sorted(entry_points.items(), key=lambda x:x[1], reverse=True))

    combinations = []
    for i in config.num_entry_points:
        for j in config.num_entry_points:
            combinations.append([i,j])
    # combinations.append([len(G.nodes()),len(G.nodes())])
    
    ### Check if experiment already performed
    df_path = pd.read_csv(config.path_stats_file_pruning)
    model,nhost,nvuln,topo,distro,diver = graph_file.replace(".graphml","").split("_")
    if diver == "1" or diver == "0": diver_cmp = int(diver)
    else: diver_cmp = float(diver)

    for setting in combinations:
        df = df_path[(df_path.model == model) & 
                    (df_path.num_host == int(nhost)) &
                    (df_path.num_vuln == int(nvuln)) &
                    (df_path.topology == topo) &
                    (df_path.distro_vuln == distro) &
                    (df_path.diversity_vuln == diver_cmp) &
                    (df_path.num_src == setting[0]) &
                    (df_path.num_target == setting[1])]
        if len(df)>0: 
            logging.debug("[ALREADY COMPUTED] %s (source:%d, target:%d)", graph_file, len(sources),len(goals))
            continue

        sources = []
        goals = []
        for entry in entry_points.keys():
            if len(sources) != setting[0]:
                sources.append(entry[0])
            if len(goals) != setting[1]:
                goals.append(entry[1])

        attack_paths = []
        # lengths = []
        for l in config.pruning_lens+[max_val]:
            startTime = time.perf_counter()
            logging.info("[START %s] path generation started (source:%d, target:%d)", graph_file, len(sources),len(goals))
            for s in sources:
                for t in goals:
                    all_paths = list(nx.all_simple_paths(G, source=s, target=t))
                    for p in all_paths:
                        attack_paths.append(p)
                        # lengths.append(len(p))
            endTime = time.perf_counter()
            logging.info("[END %s] path generation started (source:%d, target:%d)", graph_file, len(sources),len(goals))
        
            with open(config.path_stats_file_pruning, 'a', newline='') as fd:
                params_net = graph_file.replace(".graphml","").split("_")
                writer = csv.writer(fd)
                writer.writerow(params_net+[len(sources),len(goals),len(attack_paths),l,max_val,endTime-startTime])
    
    logging.info("[END] %s", graph_file)


if __name__ == "__main__":
    """
    All paths computation
    """
    reset_statistics=False
    computed_files = []
    for model in config.ag_models:
        if reset_statistics or not os.path.exists(config.path_stats_file):
            config.create_path_stats_file(reset_statistics)
        else:
            df=pd.read_csv(config.path_stats_file)
            df["filename"] = model+"_"+df["num_host"].astype(str)+"_"+\
                df["num_vuln"].astype(str)+"_"+df["topology"]+"_"+df['distro_vuln']+\
                "_"+df['diversity_vuln'].astype(str)+'.graphml'
            computed_files+=list(df["filename"])
    for elem in computed_files:
        if type(elem) != str: continue
        if "0.0" in elem: 
            newelem = elem.replace("0.0","0")
            computed_files.append(newelem)
        if "1.0" in elem: 
            newelem = elem.replace("1.0","1")
            computed_files.append(newelem)

    filenames=[]
    for filename in os.listdir(config.GRAPH_FOLDER):
        if filename not in computed_files:
            filenames.append(filename)
                                
    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(pick_entry_points, filenames, timeout=config.timeout)
    
    # """
    # Pruning paths computation
    # """
    # reset_statistics=False
    # computed_files = []
    # for model in config.ag_models:
    #     if reset_statistics or not os.path.exists(config.path_stats_file_pruning):
    #         config.create_path_stats_file_pruning(reset_statistics)
    #     else:
    #         df=pd.read_csv(config.path_stats_file_pruning)
    #         df["filename"] = model+"_"+df["num_host"].astype(str)+"_"+\
    #             df["num_vuln"].astype(str)+"_"+df["topology"]+"_"+df['distro_vuln']+\
    #             "_"+df['diversity_vuln'].astype(str)+'.graphml'
    #         computed_files+=list(df["filename"])
    # for elem in computed_files:
    #     if type(elem) != str: continue
    #     if "0.0" in elem: 
    #         newelem = elem.replace("0.0","0")
    #         computed_files.append(newelem)
    #     if "1.0" in elem: 
    #         newelem = elem.replace("1.0","1")
    #         computed_files.append(newelem)

    # filenames=[]
    # for filename in os.listdir(config.GRAPH_FOLDER):
    #     if filename not in computed_files:
    #         filenames.append(filename)
                                
    # with ProcessPool(max_workers=config.num_cores) as pool:
    #     process = pool.map(pruning, filenames, timeout=config.timeout)