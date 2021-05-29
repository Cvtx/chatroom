import random 
import logging

def get_random_username():
    return 'Гость#' + str(random.randint(1000,9999))

def setup_logger(filename: str, level, module_name: str):
    logging.basicConfig(filename=filename, level=level, format='%(asctime)s %(message)s', datefmt='%d/%m/%Y %I:%M:%S %p')        
    logging.getLogger(module_name)

