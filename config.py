import json, csv, os

### Benchmark settings
num_cores = 3
timeout = 7000
generate_all_paths = True ### NOTICE: If True, it will be much more expensive
num_entry_points = [1,5,25,50]
pruning_lens = [2,3,5,7]

### Inventories
cpe_file = "inventory/services.json"
cve_file1 = "inventory/vulnerabilities1.json"
cve_file2 = "inventory/vulnerabilities2.json"
cve_file3 = "inventory/vulnerabilities3.json"

def get_pool_vulnerabilities(tot_vuln):
    if tot_vuln <= 14500:
        with open(cve_file1) as f1:
            return json.load(f1)["vulnerabilities"]
    elif 14500 < tot_vuln <= 29000:
        with open(cve_file1) as f1, open(cve_file2) as f2:
            vulns1 = json.load(f1)["vulnerabilities"]
            vulns2 = json.load(f2)["vulnerabilities"]
            return vulns1+vulns2
    else:
        with open(cve_file1) as f1, open(cve_file2) as f2, open(cve_file3) as f3:
            vulns1 = json.load(f1)["vulnerabilities"]
            vulns2 = json.load(f2)["vulnerabilities"]
            vulns3 = json.load(f3)["vulnerabilities"]
            return vulns1+vulns2+vulns3

### Reachability configuration
nhosts = [10,25,50,75,100,150,250,500]
nvulns = [10,25,50,75,100,150,250,500]
topologies = ['mesh','random','star','ring','tree','powerlaw','lan0','lan25','lan50']
distro = ['uniform','poisson','bernoulli','binomial']
diversity = [0,0.25,0.5,0.75,1] #from all equal (0) to all diverse (1)


### File storage setting
NETWORK_FOLDER = "networks/"
MULVAL_IN_FOLDER = "mulval_inputs_few/"
MULVAL_OUT_FOLDER = "mulval_outputs/"
GRAPH_FOLDER = "attack_graphs/"

STATS_FOLDER = "analysis/"
PLOT_SPACE_FOLDER = "analysis/plot/space/"
PLOT_TIME_FOLDER = "analysis/plot/time/"
PLOT_PATH_FOLDER = "analysis/plot/path/"

path_stats_file = "analysis/path_stats.csv"
path_stats_file_pruning = "analysis/path_stats_pruning.csv"
mulval_time_file = STATS_FOLDER+"time_mulval.txt"
graph_stats_file = "graph_statistics.csv"
generation_stats_file = "generation_statistics.csv"

def create_graph_stats_file(clean_stats=False):
    if not os.path.exists(STATS_FOLDER): os.makedirs(STATS_FOLDER)
    if not os.path.exists(STATS_FOLDER+graph_stats_file) or clean_stats:
        with open(STATS_FOLDER+graph_stats_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['model','num_host','num_vuln','topology','distro_vuln',
                             'diversity_vuln','generation_time'])
            
def create_generation_stats_file(clean_stats=False):
    if not os.path.exists(STATS_FOLDER): os.makedirs(STATS_FOLDER)
    if not os.path.exists(STATS_FOLDER+generation_stats_file) or clean_stats:
        with open(STATS_FOLDER+generation_stats_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['model','num_host','num_vuln','topology','distro_vuln',
                             'diversity_vuln','num_entries','num_targets','num_paths','generation_time','generation_paths'])

### Attack Graph models settings
ag_models = ["TVA","NETSPA"] # without MulVAL
# ag_models = ["NETSPA","TVA","MULVAL"] # with MulVAL

def get_graph_structure_filename(model):
    return model+"_graph_structure.csv"

def create_graph_structural_file(model, reset=False):
    file_name=STATS_FOLDER+get_graph_structure_filename(model)
    if not os.path.exists(file_name) or reset:
        with open(file_name, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['num_host','num_vuln','topology','distro_vuln',
                             'diversity_vuln','num_nodes','num_edges','density',
                             'num_strong_components','connectivity',
                             'indegree','outdegree','close_centrality',
                             'between_centrality','time_density','time_components',
                             'time_connectivity','time_degree','time_centrality'])
      
def create_path_stats_file(reset=False):
    if not os.path.exists(path_stats_file) or reset:
        with open(path_stats_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['model','num_host','num_vuln','topology','distro_vuln',
                             'diversity_vuln','num_src','num_target','num_paths',
                             'len_path','time_path'])
            
def create_path_stats_file_pruning(reset=False):
    if not os.path.exists(path_stats_file_pruning) or reset:
        with open(path_stats_file_pruning, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['model','num_host','num_vuln','topology','distro_vuln',
                             'diversity_vuln','num_src','num_target','num_paths',
                             'len_path','s-t_distance','time_path'])