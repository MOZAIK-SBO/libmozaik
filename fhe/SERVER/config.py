from enum import Enum

class ServerConfig:

    def __init__(self, base_url: str, data_ep: str, key_ep: str, ):
        self.base_url = base_url



class OBELISKSetup(Enum):
    OBELISK_BASE = "https://mozaik.ilabt.imec.be/api"
    # ANALYSIS_REQUEST = "/TBD"
    SERVER_ID = "TBD"  # Ask Michiel to assign one - like fhe1 or sth like that - will be associated with the server secret
    SERVER_SECRET = "TBD"  # Ask Michiel to issue one - this is for JWT token authorisation to Obelisk

class FHEConfigFields(Enum):
    AUTOMORPHISM_KEY = ""
    MULTIPLICATION_KEY = ""
    ADDITION_KEY = ""
    BOOTSTRAP_KEY = ""
