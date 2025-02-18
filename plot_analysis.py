import json, csv, os.path, sys
import matplotlib.pyplot as plt
import pandas as pd
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

import config

def plot_by_graph_property(graph_param,model):
    fig, axs = plt.subplots(5, 1)
    fig.set_figwidth(20)
    fig.set_figheight(20)
    
    i=0
    for network_param in ['num_host','num_vuln','topology','distro_vuln','diversity_vuln']:
        df_model = pd.read_csv(config.STATS_FOLDER+config.get_graph_structure_filename(model))
        grouped_by_param = df_model.groupby([network_param])

        sampled_param = []
        x_labels = []
        for group, item in grouped_by_param:
            param_df = grouped_by_param.get_group(group)
            sampled_param.append(list(param_df[graph_param]))    
            x_labels.append(group)

        new_sample_param = []
        if type(sampled_param[0][0]) == str:
            sub_l_new = []
            for sub_l in sampled_param:
                sub_sub_l = sub_l[0].strip('][').split(', ')
                for elem in sub_sub_l:
                    sub_l_new.append(float(elem))
                new_sample_param.append(sub_l_new)
            sampled_param = new_sample_param
            
        axs[i].boxplot(sampled_param)
        axs[i].set_xticklabels(x_labels)
        axs[i].set_xlabel(network_param)
        axs[i].set_ylabel(graph_param)
        i+=1
    fig.suptitle(model)
    
    plt.savefig(config.PLOT_SPACE_FOLDER+graph_param+"_trendbp_"+model+".png", bbox_inches='tight')
    plt.close()

def two_params_model_structure(param_y,param_x, vertical_params, fixed_param_dict,quantile=None):
    plt.rcParams.update({'font.size': 26})
    fig, axs = plt.subplots(len(vertical_params), len(config.ag_models))
    fig.set_figwidth(30)
    fig.set_figheight(18)

    j=0
    for model in config.ag_models:
        i=0
        for param_color in vertical_params:
            df_model = pd.read_csv(config.STATS_FOLDER+config.get_graph_structure_filename(model))
            for k in fixed_param_dict.keys():
                if k != param_color and k!=param_x:
                    df_model = df_model[df_model[k] == fixed_param_dict[k]]

            grouped_by_param = df_model.groupby([param_color])
            for group, item in grouped_by_param:
                param_df = grouped_by_param.get_group(group)
                param_df = param_df.sort_values(by=[param_x])
                y_vals = list(param_df[param_y])[:9]
                x_vals = list(param_df[param_x])[:9]
                if type(y_vals[0])==str:
                    median_vals=[]
                    for k in range(0,len(y_vals)):
                        median_vals.append(json.loads(y_vals[k])[quantile])
                    axs[i][j].plot(x_vals, median_vals, label = group)
                else: 
                    axs[i][j].plot(x_vals, y_vals, label = group, linewidth = '3')
            
            axs[i][j].set_ylabel(param_y)
            axs[i][j].legend(title=param_color, loc='upper left', bbox_to_anchor=(-0.7,0.9))
            axs[i][j].set_xlabel(param_x)
            axs[i][j].set_title(model, y=0.92)
            i+=1
        j+=1

    plt.savefig(config.PLOT_SPACE_FOLDER+param_x+"_"+param_y+".png", bbox_inches='tight')
def two_params_time_by_size(param_y,param_x, vertical_params, fixed_param_dict,quantile=None):
    plt.rcParams.update({'font.size': 26})
    fig, axs = plt.subplots(len(vertical_params), len(config.ag_models))
    fig.set_figwidth(25)
    fig.set_figheight(18)

    df = pd.read_csv(config.STATS_FOLDER+config.graph_stats_file)

    j=0
    for model in config.ag_models:
        i=0
        for param_color in vertical_params:
            df_model = df[df["model"] == model]
            for k in fixed_param_dict.keys():
                if k != param_color and k!=param_x:
                    df_model = df_model[df_model[k] == fixed_param_dict[k]]

            grouped_by_param = df_model.groupby([param_color])
            for group, item in grouped_by_param:
                param_df = grouped_by_param.get_group(group)
                param_df = param_df.sort_values(by=[param_x])
                y_vals = list(param_df[param_y])#[:9]
                x_vals = list(param_df[param_x])#[:9]
                if type(y_vals[0])==str:
                    median_vals=[]
                    boxes=[]
                    for k in range(0,len(y_vals)):
                        median_vals.append(json.loads(y_vals[k])[quantile])
                    axs[i][j].plot(x_vals, median_vals, label = group)
                else: 
                    axs[i][j].plot(x_vals, y_vals, label = group, linewidth = '3')
            
            if j==0:
                axs[i][j].set_ylabel(param_y)
                axs[i][j].legend(title=param_color, loc='upper left')
            axs[i][j].set_xlabel(param_x)
            axs[i][j].set_title(model)
            i+=1
        j+=1

    plt.savefig(config.PLOT_TIME_FOLDER+param_x+"_"+param_y+"_params.png", bbox_inches='tight')
    
def two_params_graph_statistics(param_y,param_x, vertical_params, fixed_param_dict):
    plt.rcParams.update({'font.size': 14})
    fig, axs = plt.subplots(len(vertical_params), len(config.ag_models))
    fig.set_figwidth(20)
    fig.set_figheight(20)
    df = pd.read_csv(config.STATS_FOLDER+config.graph_stats_file)

    j=0
    for model in config.ag_models:
        i=0
        for param_color in vertical_params:
            df_model = df[df["model"] == model]
            for k in fixed_param_dict.keys():
                if k != param_color and k!=param_x:
                    df_model = df_model[df_model[k] == fixed_param_dict[k]]

            grouped_by_param = df_model.groupby([param_color])
            for group, item in grouped_by_param:
                param_df = grouped_by_param.get_group(group)
                param_df = param_df.sort_values(by=[param_x])
                y_vals = list(param_df[param_y])[:-1]
                x_vals = list(param_df[param_x])[:-1]
                axs[i][j].plot(x_vals, y_vals, label = group)

            axs[i][j].set_xlabel(param_x)
            axs[i][j].set_ylabel(param_y)
            axs[i][j].legend(title=param_color)
            axs[i][j].set_title(model)
            i+=1
        j+=1

    plt.savefig(config.PLOT_TIME_FOLDER+param_x+"_"+param_y+".png", bbox_inches='tight')
def two_params_graph_statistics_simple(param_y,param_x, fixed_param_dict):
    plt.rcParams.update({'font.size': 24})
    fig, axs = plt.subplots()
    fig.set_figwidth(10)
    fig.set_figheight(10)
    df = pd.read_csv(config.STATS_FOLDER+config.graph_stats_file)

    models_proc = []
    for model in config.ag_models:
        df_model = df[df["model"] == model]
        for k in fixed_param_dict.keys():
            if k!=param_x:
                df_model = df_model[df_model[k] == fixed_param_dict[k]]

        # grouped_by_param = df_model.groupby([param_color])
        # for group, item in grouped_by_param:
        #     param_df = grouped_by_param.get_group(group)
        param_df = df_model.sort_values(by=[param_x])
        y_vals = list(param_df[param_y])#[:-1]
        x_vals = list(param_df[param_x])#[:-1]
        axs.plot(x_vals, y_vals,linewidth = '3')
        models_proc.append(model)

    axs.set_xlabel(param_x)
    axs.set_ylabel(param_y)
    axs.legend(models_proc)
    # axs.set_title(model)

    plt.savefig(config.PLOT_TIME_FOLDER+param_x+"_"+param_y+".png", bbox_inches='tight')
def two_params_by_size(param_y,param_x, fixed_param_dict):
    plt.rcParams.update({'font.size': 24})
    fig, axs = plt.subplots()
    fig.set_figwidth(10)
    fig.set_figheight(10)
    df = pd.read_csv(config.STATS_FOLDER+config.graph_stats_file)

    models_proc = []
    for model in config.ag_models:
        if model=="MULTI": continue
        df_model = df[df["model"] == model]
        for k in fixed_param_dict.keys():
            if k!=param_x:
                df_model = df_model[df_model[k] == fixed_param_dict[k]]

        # grouped_by_param = df_model.groupby([param_color])
        # for group, item in grouped_by_param:
        #     param_df = grouped_by_param.get_group(group)
        param_df = df_model.sort_values(by=[param_x])
        y_vals = list(param_df[param_y])#[:-1]
        x_vals_ = list(param_df[param_x])#[:-1]
        if param_x == "num_host": x_vals = [x * fixed_param_dict["num_vuln"] for x in x_vals_]
        else: x_vals = [x * fixed_param_dict["num_host"] for x in x_vals_]
        axs.plot(x_vals, y_vals,linewidth = '3')
        models_proc.append(model)


    # axs.set_xlabel(param_x)
    axs.set_xlabel("inventory size (#hosts * #vulns)")
    # axs.set_ylabel(param_y+" (s)")
    axs.set_ylabel("generation time (s)")
    axs.set_xlim(0,50000)
    axs.set_ylim(0,10000)
    axs.legend(models_proc,loc='upper left')
    # axs.set_title(model)

    plt.savefig(config.PLOT_TIME_FOLDER+param_x+"_"+param_y+"_size.png", bbox_inches='tight')
def two_params_space_by_size(param_y,param_x,vertical_params,fixed_param_dict):
    plt.rcParams.update({'font.size': 24})
    fig, axs = plt.subplots()
    fig.set_figwidth(10)
    fig.set_figheight(10)

    models_proc = []
    for model in config.ag_models:
        df_model = pd.read_csv(config.STATS_FOLDER+config.get_graph_structure_filename(model))
        for k in fixed_param_dict.keys():
            if k!=param_x:
                df_model = df_model[df_model[k] == fixed_param_dict[k]]
        
        param_df = df_model.sort_values(by=[param_x])
        y_vals = list(param_df[param_y])#[:-1]
        x_vals_ = list(param_df[param_x])#[:-1]
        if param_x == "num_host": x_vals = [x * fixed_param_dict["num_vuln"] for x in x_vals_]
        else: x_vals = [x * fixed_param_dict["num_host"] for x in x_vals_]
        axs.plot(x_vals, y_vals,linewidth = '3')
        models_proc.append(model)


    # axs.set_xlabel(param_x)
    axs.set_xlabel("inventory size (#hosts * #vulns)")
    # axs.set_ylabel(param_y+" (s)")
    axs.set_ylabel("# edges")
    axs.set_xlim(0,6000)
    axs.set_ylim(0,80000)
    axs.legend(models_proc)
    # axs.set_title(model)

    plt.savefig(config.PLOT_SPACE_FOLDER+param_x+"_"+param_y+"_size.png", bbox_inches='tight')

def two_params_path_statistics(param_y,param_x, vertical_params, fixed_param_dict,quantile=2):
    plt.rcParams.update({'font.size': 14})
    fig, axs = plt.subplots(len(vertical_params), len(config.ag_models))
    fig.set_figwidth(20)
    fig.set_figheight(20)
    df = pd.read_csv(config.path_stats_file)

    j=0
    for model in config.ag_models:
        i=0
        for param_color in vertical_params:
            df_model = df[df["model"] == model]
            for k in fixed_param_dict.keys():
                if k != param_color and k!=param_x:
                    df_model = df_model[df_model[k] == fixed_param_dict[k]]

            grouped_by_param = df_model.groupby([param_color])
            for group, item in grouped_by_param:
                param_df = grouped_by_param.get_group(group)
                param_df = param_df.sort_values(by=[param_x])
                y_vals = list(param_df[param_y])[:-2]
                x_vals = list(param_df[param_x])[:-2]
                if type(y_vals[0])==str:
                    median_vals=[]
                    for k in range(0,len(y_vals)):
                        median_vals.append(json.loads(y_vals[k])[quantile])
                    axs[i][j].plot(x_vals, median_vals, label = group)
                else: 
                    axs[i][j].plot(x_vals, y_vals, label = group)
            
            axs[i][j].legend(title=param_color)
            axs[i][j].set_xlabel(param_x)
            axs[i][j].set_ylabel(param_y)
            axs[i][j].set_title(model)
            i+=1
        j+=1

    plt.savefig(config.PLOT_PATH_FOLDER+param_x+"_"+param_y+".png", bbox_inches='tight')

def fill_intractable_path():
    df_path = pd.read_csv(config.path_stats_file)
    max_time = max(list(df_path["time_path"]))+1800
    max_path = max(list(df_path["num_paths"]))+1800

    for model in ["TVA","NETSPA"]:
        for n in config.nhosts:
            for v in config.nvulns:
                for t in config.topologies:
                    for d in config.distro:
                        for u in config.diversity:
                            for num_s in config.num_entry_points:
                                for num_t in config.num_entry_points:
                                    df = df_path[(df_path.model == model) & 
                                    (df_path.num_host == n) &
                                    (df_path.num_vuln == v) &
                                    (df_path.topology == t) &
                                    (df_path.distro_vuln == d) &
                                    (df_path.diversity_vuln == u) &
                                    (df_path.num_src == num_s) &
                                    (df_path.num_target == num_t)]
                                    if len(df)<=0:
                                        if (t=="mesh" or t=="random") and d=="uniform":
                                            # print(model,v,v,t,d,u,num_s,num_t,max_path,max_time) 
                                            with open(config.path_stats_file, 'a', newline='') as fd:
                                                writer = csv.writer(fd)
                                                writer.writerow([model,n,v,t,d,u,
                                                                num_s,num_t,max_path,"[0.0, 0.0, 0.0, 0.0, 0.0]",max_time])

    # for ag_file in os.listdir(config.GRAPH_FOLDER):
    #     if "real" not in ag_file:
    #         model,nhost,nvuln,topo,distro,diver = ag_file.replace(".graphml","").split("_")
            # for num_s in config.num_entry_points:
            #     for num_t in config.num_entry_points:
            #         if diver == "1" or diver == "0": diver_cmp = int(diver)
            #         else: diver_cmp = float(diver)
            #         df = df_path[(df_path.model == model) & 
            #                     (df_path.num_host == int(nhost)) &
            #                     (df_path.num_vuln == int(nvuln)) &
            #                     (df_path.topology == topo) &
            #                     (df_path.distro_vuln == distro) &
            #                     (df_path.diversity_vuln == diver_cmp) &
            #                     (df_path.num_src == num_s) &
            #                     (df_path.num_target == num_t)]
                    # if len(df)<=0:
                    #     if "MULVAL" not in ag_file:
                    #         if "mesh_uniform_0" in ag_file or "mesh_uniform_1" in ag_file or "random_uniform_0" in ag_file or "random_uniform_1" in ag_file:
                    #             with open(config.path_stats_file, 'a', newline='') as fd:
                    #                 writer = csv.writer(fd)
                    #                 writer.writerow([model,nhost,nvuln,topo,distro,diver,
                    #                                 num_s,num_t,max_path,"[0.0, 0.0, 0.0, 0.0, 0.0]",max_time])

def get_num(val):
    if val == 1: return 1
    elif val == 2: return 3
    elif val == 3: return 10
    elif val == 4: return 50

from matplotlib.lines import Line2D
def get_color(val, all_vals):
    all_vals = [i for i in all_vals if i != 0]
    # if val <= np.quantile(all_vals, 0.4): return "#008837"
    # elif  val >np.quantile(all_vals, 0.4) and val <= np.quantile(all_vals, 0.6): return "#c2a5cf"
    # else: return "#7b3294"
    if val <= 3600: return "#008837"
    elif  val >3600 and val <= 7000: return "#c2a5cf"
    else: return "#7b3294"
def _3dplot(param_x, param_y, param_z, model, fixed_param_dict):
    df_path = pd.read_csv("analysis/path_stats.csv")
    
    df_model = df_path[df_path["model"] == model]
    for k in fixed_param_dict.keys():
        if k != param_z and k!=param_x and k!=param_y:
            df_model = df_model[df_model[k] == fixed_param_dict[k]]
    
    vals_stats = list(df_model[(df_model.model == model)][param_z])
    max_val = 7100#max(vals_stats)

    fig = plt.figure()
    ax = fig.add_subplot(projection='3d')

    # vals_hosts = list(df_model[(df_model.model == model)][param_y])
    # vals_vuln = list(df_model[(df_model.model == model)][param_x])
    # vals_hosts = [item for item in vals_hosts if item <= 50]
    # vals_vuln = [item for item in vals_vuln if item <= 50]
    # xs = sorted(list(set(vals_hosts)))
    # ys = sorted(list(set(vals_vuln)))
    xs = config.nhosts
    ys = config.nvulns

    # print(vals_stats)
    # new_vals=[]
    # for elem in vals_stats:
    #     if elem<=1000: new_vals.append(1000)
    #     else: new_vals.append(elem)
    # print(new_vals)

    for s in ys:
        z_all=[]
        cols=[]
        for t in xs:
            df = df_model[(df_model.model == model) & 
                (df_model[param_y] == s) &
                (df_model[param_x] == t)]
            zval = df[param_z]
            if len(zval)>0:
                if float(zval)<50:
                    z_all.append(50)
                    cols.append(get_color(50,vals_stats))
                else:
                    z_all.append(float(zval))
                    cols.append(get_color(float(zval),vals_stats))
            else:
                if s>50 and t>50:
                    z_all.append(max_val)
                    cols.append(get_color(max_val,vals_stats))
                else:
                    z_all.append(0)
                    cols.append(get_color(0,vals_stats))
        xs.pop()
        xs.append(200)
        ax.bar(xs, z_all, zs=s, zdir='y', color=cols, alpha=0.8, width=8)
    
    ax.invert_xaxis()

    ax.set_xlabel(param_x)
    # ax.set_xticklabels(xs)
    ax.set_ylabel(param_y)
    # ax.set_yticklabels(ys)
    ax.set_zlabel(param_z)

    ax.set_yticks(ys)
    ax.set_title(model)

    custom_lines = [Line2D([0], [0], color='#008837', lw=4),
                Line2D([0], [0], color="#c2a5cf", lw=4),
                Line2D([0], [0], color="#7b3294", lw=4)]
    ax.legend(custom_lines, ['<1hr', '<2hr', '>2hr'])
    ax.set_title("Vuln. diversity: "+str(fixed_param_dict["diversity_vuln"]), y=1.0, pad=-2)

    plt.savefig(config.PLOT_PATH_FOLDER+model+"_"+param_z+"_"+
        str(fixed_param_dict["diversity_vuln"])+".png", bbox_inches='tight')
    

def _3dplot_host_vuln(param_x, param_y, param_z, model, fixed_param_dict):
    df_model = pd.read_csv(config.STATS_FOLDER+config.get_graph_structure_filename(model))
    
    for k in fixed_param_dict.keys():
        if k != param_z and k!=param_x and k!=param_y:
            df_model = df_model[df_model[k] == fixed_param_dict[k]]
    
    vals_stats = list(df_model[param_z])

    fig = plt.figure()
    ax = fig.add_subplot(projection='3d')

    vals_hosts = list(df_model[param_y])
    vals_vuln = list(df_model[param_x])
    ys = sorted(list(set(vals_hosts)))
    xs = sorted(list(set(vals_vuln)))

    for s in ys:
        z_all=[]
        cols=[]
        for t in xs:
            df = df_model[(df_model[param_y] == s) &
                (df_model[param_x] == t)]
            zval = df[param_z]
            if len(zval)>0:
                z_all.append(float(zval))
                cols.append(get_color(float(zval),vals_stats))
            else:
                z_all.append(0)
                cols.append(get_color(0,vals_stats))

        ax.bar(xs, z_all, zs=s, zdir='y', color=cols, alpha=0.8, width=15)

    ax.invert_xaxis()

    ax.set_xlabel(param_x)
    ax.set_xticklabels(xs)
    ax.set_ylabel(param_y)
    ax.set_yticklabels(ys)
    ax.set_zlabel(param_z)

    # ax.set_yticks(ys)
    ax.set_title(model)

    plt.savefig(config.PLOT_SPACE_FOLDER+model+"_"+param_z+"_"+
        str(fixed_param_dict["diversity_vuln"])+".png", bbox_inches='tight')

def _3dplot_host_vuln_time(param_x, param_y, param_z, model, fixed_param_dict):
    plt.rcParams.update({'font.size': 14})
    df_generation = pd.read_csv(config.STATS_FOLDER+config.graph_stats_file)
    
    for k in fixed_param_dict.keys():
        if k != param_z and k!=param_x and k!=param_y:
            df_generation = df_generation[df_generation[k] == fixed_param_dict[k]]
    df_model=df_generation[df_generation["model"] == model]

    vals_stats = list(df_model[param_z])

    fig = plt.figure()
    ax = fig.add_subplot(projection='3d')

    vals_hosts = list(df_model[param_y])
    vals_vuln = list(df_model[param_x])
    ys = sorted(list(set(vals_hosts)))[:-2]
    xs = sorted(list(set(vals_vuln)))[:-1]

    # ys = [6,5,4,3,2,1]
    # xs = [1,2,3,4,5,6]
    for s in ys:
        z_all=[]
        cols=[]
        for t in xs:
            df = df_model[(df_model[param_y] == s) &
                (df_model[param_x] == t)]
            zval = df[param_z]
            if len(zval)>0:
                zval_ = max(zval)
                if zval_<=10: zval_=100
                if zval_>=30000: zval_=30000
                z_all.append(float(zval_))
                cols.append(get_color(float(zval_),vals_stats))
            else:
                z_all.append(0)
                cols.append(get_color(0,vals_stats))

        ax.bar(xs, z_all, zs=s, zdir='y', color=cols, alpha=0.8, width=15)

    ax.invert_xaxis()

    ax.set_xlabel(param_x)
    # ax.set_xticklabels(xs)
    ax.set_xticks(xs)
    ax.set_ylabel(param_y)
    # ax.set_yticklabels(ys)
    ax.set_yticks(ys)
    ax.set_zlabel(param_z)

    # ax.set_yticks(ys)
    ax.set_title(model)

    custom_lines = [Line2D([0], [0], color='#008837', lw=4),
                Line2D([0], [0], color="#c2a5cf", lw=4),
                Line2D([0], [0], color="#7b3294", lw=4)]
    ax.legend(custom_lines, ['<1hr', '<2hr', '>2hr'])

    plt.savefig(config.PLOT_TIME_FOLDER+model+"_"+param_z+"_"+
        str(fixed_param_dict["diversity_vuln"])+".png", bbox_inches='tight')


def two_params_model_distro(param_y,param_x, vertical_params, fixed_param_dict,quantile=None):
    plt.rcParams.update({'font.size': 26})
    fig, axs = plt.subplots(len(vertical_params), len(config.ag_models))
    fig.set_figwidth(30)
    fig.set_figheight(18)

    j=0
    for model in ["DISTRO"]:#config.ag_models:
        i=0
        for param_color in vertical_params:
            df_model = pd.read_csv(config.STATS_FOLDER+"distributed_statistics.csv")#config.get_graph_structure_filename(model))
            for k in fixed_param_dict.keys():
                if k != param_color and k!=param_x:
                    df_model = df_model[df_model[k] == fixed_param_dict[k]]

            y_vals=[]
            x_vals=[]
            grouped_by_param = df_model.groupby([param_color])
            for group, item in grouped_by_param:
                param_df = grouped_by_param.get_group(group)
                param_df = param_df.sort_values(by=[param_x])
                y_vals += list(param_df[param_y])#[:9]
                x_vals += list(param_df[param_x])#[:9]
            
            if type(y_vals[0])==str:
                median_vals=[]
                for k in range(0,len(y_vals)):
                    median_vals.append(json.loads(y_vals[k])[quantile])
                axs[i][j].plot(x_vals, median_vals, label = group)
            else: 
                x_vals.sort()
                y_vals.sort()
                axs[i][j].plot(x_vals, y_vals, label = group, linewidth = '3')
            
            axs[i][j].set_ylabel(param_y)
            axs[i][j].legend(title=param_color, loc='upper left', bbox_to_anchor=(-0.7,0.9))
            axs[i][j].set_xlabel(param_x)
            axs[i][j].set_title(model, y=0.92)
            i+=1
        j+=1

    plt.savefig(config.PLOT_SPACE_FOLDER+param_x+"_"+param_y+".png", bbox_inches='tight')



if __name__ == "__main__":

    if not os.path.exists(config.PLOT_SPACE_FOLDER): os.makedirs(config.PLOT_SPACE_FOLDER)
    if not os.path.exists(config.PLOT_TIME_FOLDER): os.makedirs(config.PLOT_TIME_FOLDER)
    if not os.path.exists(config.PLOT_PATH_FOLDER): os.makedirs(config.PLOT_PATH_FOLDER)

    fixed_param={
        'num_host': 10,
        "num_vuln": 25,
        "diversity_vuln":0,
        'topology': "star",
        'distro_vuln': "uniform",
        # 'num_src': 1,
        # 'num_target': 5
    }
    main_param_net="num_host"
    color_params_net = ['diversity_vuln','topology']#,'distro_vuln']

    two_params_model_distro("avg_generation_time",main_param_net, color_params_net, fixed_param)

    # for param in ['num_edges']:#,'num_nodes','density','num_strong_components']:
    #     quantile=4
    #     two_params_model_structure(param,main_param_net,color_params_net,fixed_param,quantile)
    #     # two_params_space_by_size(param,main_param_net,color_params_net,fixed_param)
    
    # for param_time in ['generation_time']:
    #     two_params_by_size(param_time,main_param_net,fixed_param)
    #     two_params_time_by_size(param_time,main_param_net,color_params_net,fixed_param)

    #     for model in config.ag_models:
    #         _3dplot_host_vuln_time('num_host', 'num_vuln', param_time, model, fixed_param)

    # # fill_intractable_path()

    # for param_path in ['num_paths','time_path']:
    #     quantile_len=2
    #     two_params_path_statistics(param_path,main_param_net,color_params_net,fixed_param,quantile_len)


    # for model in config.ag_models:
    #     for param_z in ["time_path"]:#,"num_paths"]:
    #         _3dplot("num_host", "num_vuln", param_z, model,fixed_param)

    # for model in config.ag_models:
    #     for param_z in ['num_edges']: # 'num_nodes','density','num_strong_components','time_density','time_components','time_degree','time_centrality']:
    #         _3dplot_host_vuln('num_host', 'num_vuln', param_z, model, fixed_param)