import subprocess

import sys
from pathlib import Path
from config import FHEConfigFields

class FHEContext:

    def __init__(self, inference_binary_path_str: str):
        self.network_path = Path(inference_binary_path_str)
        assert self.network_path.exists()

    def run_inference(self, crypto_config_path_str: str, ct_path_str: str):
        assert crypto_config_path_str.endswith(".json")
        crypto_path = Path(crypto_config_path_str)
        assert crypto_path.exists(follow_symlinks=True)

        ct_path = Path(ct_path_str)
        assert ct_path.exists(follow_symlinks=True)

        proc_result = subprocess.run([self.network_path.absolute(), crypto_path.absolute(), ct_path.absolute()], capture_output=True)

        if proc_result.returncode != 0:
            print("[!] An error has occurred during inference", file=sys.stderr)
            print(proc_result.stdout, file=sys.stderr)


