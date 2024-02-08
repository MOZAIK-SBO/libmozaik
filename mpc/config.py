import tomli as tomllib

class Config:
    def __init__(self, config_path):
        self.config = self.load_config(config_path)
        
        self.CONFIG_RESULTS_DIR = self.config['results_dir']
        self.CONFIG_PORT = self.config['port']
        self.CONFIG_CA_CERT = self.config['ca_cert']
        self.CONFIG_SERVER_CERT = self.config['server_cert']
        self.CONFIG_SERVER_KEY = self.config['server_key']
        self.CONFIG_PARTY_INDEX = self.config['party_index']


    def load_config(self, config_path):
        with open(config_path, 'rb') as fp:
            return tomllib.load(fp)

