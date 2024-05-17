from enum import Enum

class FHEEndpoints(Enum):
    OBELISK_PULL = "/TBD"
    OBELISK_PUSH = "/TBD"
    ANALYSIS_REQUEST = "/TBD"

class FHEConfigFields(Enum):
    AUTOMORPHISM_KEY = ""
    MULTIPLICATION_KEY = ""
    ADDITION_KEY = ""
    BOOTSTRAP_KEY = ""
