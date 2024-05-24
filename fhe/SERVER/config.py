from enum import Enum

class ServerConfig:

    def __init__(self, base_url: str, data_ep: str, key_ep: str, ):
        self.base_url = base_url



class FHEEndpoints(Enum):
    OBELISK_PULL = "/TBD"
    OBELISK_PUSH = "/TBD"
    ANALYSIS_REQUEST = "/TBD"

class FHEConfigFields(Enum):
    AUTOMORPHISM_KEY = ""
    MULTIPLICATION_KEY = ""
    ADDITION_KEY = ""
    BOOTSTRAP_KEY = ""
