import os, logging, sys
from pebble import ProcessPool

from utils.dump_nvd import dump
from utils.generate_reachability import write_reachability
import config

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
logger = logging.getLogger(__name__)
logfile = 'logging/network.log'

"""
Generate the benchmark of networks in "network" folder
"""
def generate_network(filename):
    logging.basicConfig(filename=logfile, level=logging.DEBUG, filemode='w', format='%(asctime)s - %(levelname)s: %(message)s')
    
    if not os.path.exists(config.NETWORK_FOLDER): os.makedirs(config.NETWORK_FOLDER)
    generated_files = os.listdir(config.NETWORK_FOLDER)
    if filename not in generated_files:
        write_reachability(config.NETWORK_FOLDER,filename)
        logging.info("Generated network: %s (total generated files - %d)", filename, len(generated_files))
    else:
        logging.debug("[Already Generated]: %s (total generated files - %d)", filename, len(generated_files))

if __name__ == "__main__":
    
    """
    To build the inventory from skratch
    NOTICE: this may require long time for NIST APIs. We suggest to use the 
    proposed syntetic inventory
    """
    # dump()

    """
    Create networks for reachability graphs
    """
    filenames=[]
    for n in config.nhosts:
        for v in config.nvulns:
            for t in config.topologies:
                for d in config.distro:
                    for u in config.diversity:
                        filename = str(n)+'_'+str(v)+'_'+t+'_'+d+'_'+str(u)+'.json'
                        filenames.append(filename)
    
    """
    Generate Reachability Networks
    """
    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(generate_network, filenames)