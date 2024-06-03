from enum import Enum

class OBELISKSetup(Enum):
    OBELISK_BASE = "https://mozaik.ilabt.imec.be/api"
    # ANALYSIS_REQUEST = "/TBD"
    SERVER_ID = "TBD"  # Ask Michiel to assign one - like fhe1 or sth like that - will be associated with the server secret
    SERVER_SECRET = "TBD"  # Ask Michiel to issue one - this is for JWT token authorisation to Obelisk

