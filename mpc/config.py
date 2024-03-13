import tomli as tomllib

class Config:
    """
    Config class manages configuration settings.

    Attributes:
        config: The loaded configuration settings.
        CONFIG_RESULTS_DIR: The directory where results are stored.
        CONFIG_PORT: The port number.
        CONFIG_CA_CERT: The path to the CA certificate file.
        CONFIG_SERVER_CERT: The path to the server certificate file.
        CONFIG_SERVER_KEY: The path to the server key file.
        CONFIG_PARTY_INDEX: The index of the party.
        CONFIG_SERVER_ID: Server id for auth to obelisk
        CONFIG_SERVER_SECRET: Server secret for auth to obelisk
    """
    def __init__(self, config_path):
        """
        Initialize Config with the provided parameters.

        Arguments:
            config_path (str) : The path to the configuration file.
        """
        self.config = self.load_config(config_path)
        
        self.CONFIG_RESULTS_DIR = self.config['results_dir']
        self.CONFIG_PORT = self.config['port']
        self.CONFIG_CA_CERT = self.config['ca_cert']
        self.CONFIG_SERVER_CERT = self.config['server_cert']
        self.CONFIG_SERVER_KEY = self.config['server_key']
        self.CONFIG_PARTY_INDEX = self.config['party_index']
        self.CONFIG_SERVER_ID = self.config['server_id']    
        self.CONFIG_SERVER_SECRET = self.config['server_secret']  


    def load_config(self, config_path):
        """
        Load the configuration settings from a TOML file.

        Arguments:
            config_path (str) : The path to the configuration file.

        Returns:
            The loaded configuration settings.
        """
        with open(config_path, 'rb') as fp:
            return tomllib.load(fp)
        
    def keys_config(self):
        """
        Generate configuration settings for keys.

        Returns:
            A dictionary containing configuration settings for keys.
        """
        party_keys = ['tls_certs/server1.crt', 'tls_certs/server2.crt', 'tls_certs/server3.crt']
        return {
            "server_key": f'tls_certs/server{self.CONFIG_PARTY_INDEX+1}.key',
            "server_cert": f'tls_certs/server{self.CONFIG_PARTY_INDEX+1}.crt',
            "party_index": self.CONFIG_PARTY_INDEX,
            "party_certs": party_keys
        }

