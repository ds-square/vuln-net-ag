# Behind the Scenes of Attack Graphs: Vulnerable Network Generator for In-Depth Experimental Evaluation of Attack Graph Scalability

## Abstract

An Attack Graph represents potential paths for attackers to compromise a computer network and security analysts use it to pinpoint vulnerable areas for cyber risk assessment.
Due to their combinatorial complexity, designing scalable algorithms for generating these graphs without sacrificing their accuracy remains a challenge.
Previous research focused on improving scalability, but evaluations often overlooked key parameters beyond network size, thus raising the natural question of their application in real-world settings.
One of the main causes is the lack of data that the cybersecurity community faces in different areas, and cyber risk assessment in particular.
To address this problem and support the comprehensive evaluation of attack graph algorithms, we introduce a dataset generator of vulnerable networks, which includes reachability graphs and vulnerability inventories.
This enables the design of an analytical framework to assess attack graph scalability comprehensively, considering diverse network and vulnerability dimensions.
According to the proposed framework, we perform in-depth experimental evaluation of the time and space complexities of attack graphs offering novel insights into the critical parameters affecting them, and we extensively discuss how they inform and benefit future approaches.

## Requirements:

The following libraries and packages are required for the correct installation of the benchmark:

- pandas
- networkx
- Pebble
- numpy
- matplotlib
- nvdlib
- scikit-learn
- scipy
- stats

To install the requirements:

```
pip install requirements
```

## Instructions

Given the multiple contributions of the paper and this repository, we provide a modular approach to run the system, so as the user can run only the portion of the code s/he is interested in.
The code is set to run on multiple cores given the required computational time. The number of cores and the dataset generator parameters can be set in the config.py file.

### Vulnerable Network Generator

1. Set up the generator parameters in the file `config.py` under the section `###[Vulnerable Network Generator]`

1. If you change default `OS` and `SERVICES`, uncomment the `dump()` function in the main.
   NOTE 1: dumping services and vulnerabilities from NVD repository may require time.
   NOTE 2: for a better service, create your `nvd api key` (https://nvd.nist.gov/developers/request-an-api-key) and put it in the configuration file (`config.py`)

1. Run the network generator using the following command (generated network files will appear in the `networks` folder)

`python3 main_network_generator`

### Attack Graph Generation

```
python3 main_ag_modeling.py
```

Run Attack Graph generation according to NetSPA and TVA. The results of this module is the dataset of attack graphs (in graphml format) in "attack_graphs" folder.
MulVAL is excluded by default, if you want to add MulVAL in the analysis, update the config.py file. More information available in the next section "Instructions for MulVAL".
NOTICE: MulVAL must be generated using the propietary tool available at: https://people.cs.ksu.edu/~xou/mulval/

Additionally, this module computes the structural analysis to retrieve graph properties of attack graphs (e.g., centrality, connectivity, strong components). The results will be available for each model in an appropriate file in the "analysis" folder.

NOTICE: It is necessary to generate vulnerable networks before running this module.

### 4. Compute attack paths

```
python3 main_path_computation.py
```

Run the path computation module to compute the possible attack paths for each generated attack graph and store information about scalability (i.e., computation time and number of paths). Notice that this module may be computationally expensive, thus it is optional based on user needs.

### 5. Analyze the results

```
python3 plot_analysis.py
```

Some precomputed plots are available in plot_analysis.py script.

# Instructions for MulVAL

Since MulVAL is tested used the proprietary project (https://people.cs.ksu.edu/~xou/mulval/), some further steps are necessary for the analysis of it.

NOTICE: MulVAL is available only for Linux os.

### 1. Install MulVAL (https://people.cs.ksu.edu/~xou/mulval/)

### 2. Generate MulVAL inputs

```
python3 algorithms/mulval.py
```

After the generation of network inventories (step2 of previous section), uncomment the first part of the main module from the script "algorithms/mulval.py": it generates the inputs for the MulVAL project according to the required format in the "mulval_inputs" folder.

### 3. Generate MulVAL attack graphs

Generate the attack graph according to MulVAL project instruction. We provide a bash script to auotmatically process input files. The file "exec_mulval.sh" pick files from a folder "dataset" and generate attack graph automatically, keeping track of the required generation time in the "time_log.txt" file. It works with a slight modification of the MulVAL main that we also provide in the mulval_util folder: you should replace the file graph_gen.sh in our folder in the mulval/utils folder of the original project.

Once processed, put all the generated ARCS.csv, VERTICES.csv, and AttackGraph.txt files in the "mulval_output" folder, and the file "time_log.txt" in the analysis folder.

### 4. Generate MulVAL graph-based models

```
python3 algorithms/mulval.py
```

Uncomment the second part of the main module of the script "algorithms/mulval.py": it generates the graphml representation of MulVAL attack graphs.

### 5. Compute structural and path analyses

Perform the steps of the previous section starting from 3.
