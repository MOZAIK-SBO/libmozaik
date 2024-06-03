from tempfile import NamedTemporaryFile
from pathlib import Path
from base64 import urlsafe_b64encode, urlsafe_b64decode

import json
import subprocess


class FHEDataManager:

    key_cache_name = "keys"
    model_cache_name = "models"
    expected_keys = ["automorphism_key","multiplication_key","crypto_context"]

    def __init__(self, base_path="./", max_cache_size=10, encoding="JSON"):
        self.base_path = Path(base_path)
        assert self.base_path.exists()

        self.bin = self.base_path / "bin"
        self.key_cache = self.base_path / "cache" / self.key_cache_name
        self.neural_net_cache = self.base_path / "cache" / self.model_cache_name
        self.max_cache_size = max_cache_size
        self.ciphertext_dir = self.base_path / "ct"
        self.encoding = encoding

        if not self.key_cache.exists():
            self.key_cache.mkdir(parents=True, exist_ok=True)

        if not self.neural_net_cache.exists():
            self.neural_net_cache.mkdir(parents=True, exist_ok=True)

    def get_user_keys_from_cache(self, user_id: str):
        user_key_dir = self.key_cache / user_id
        ok = user_key_dir.exists()
        for key in self.expected_keys:
            key_path = user_key_dir / key
            ok = ok and key_path.exists()

        config_path = user_key_dir / "crypto_config.json"
        ok = ok and config_path.exists()

        return ok, str(config_path.absolute()) if ok else ""

    def is_neural_net_in_cache(self, analysis_type: str):
        analysis_dir = self.neural_net_cache / analysis_type
        return analysis_dir.exists()

    def put_keys_into_cache(self, user_id: str, auto_key: str, mult_key: str, crypto_context: str):
        all_keys = [auto_key, mult_key,crypto_context]
        user_key_dir = self.key_cache / user_id

        # Ensure the user key directory exists
        user_key_dir.mkdir(parents=True, exist_ok=True)

        # Transform keys back to bytes
        for name, key in zip(self.expected_keys, all_keys):
            key_file = user_key_dir / name
            if self.encoding != "JSON":
                key_raw = self.decode_to_raw(key)
                with key_file.open("wb") as F:
                    F.write(key_raw)
            else:
                with key_file.open("w") as F:
                    F.write(key)

    def generate_config(self, user_id: str, analysis_type:str):
        user_key_dir = self.key_cache / user_id
        config = {}
        for key in self.expected_keys:
            key_file = user_key_dir / key
            config[key] = str(key_file.absolute())
        nn_path = self.neural_net_cache / analysis_type / "config.json"
        config["neural_network_config"] = str(nn_path.absolute())

        config_path = user_key_dir / "crypto_config.json"
        with config_path.open("w") as F:
            F.write(json.dumps(config))

        return str(config_path.absolute())

    def put_ct_into_dir(self, user_id: str, ct_name:str, ct_content: str):
        user_ct_dir = self.ciphertext_dir / user_id

        if not user_ct_dir.exists():
            user_ct_dir.mkdir(parents=True)

        if user_ct_dir.exists() and user_ct_dir.is_dir():
            ct_path = user_ct_dir / ct_name
            if self.encoding != "JSON":
                with ct_path.open("wb") as F:
                    ct_content_raw = self.decode_to_raw(ct_content)
                    F.write(ct_content_raw)
            else:
                with ct_path.open("w") as F:
                    F.write(ct_content)
            return str(ct_path.absolute())

        return ""

    def get_user_ct_from_cache(self, user_id:str, data_index:str):
        ct_path = self.ciphertext_dir / user_id / data_index
        return ct_path.exists(), str(ct_path.absolute()) if ct_path.exists() else ""

    @staticmethod
    def encode_from_raw(data: bytes):
        return urlsafe_b64encode(data)

    @staticmethod
    def decode_to_raw(data: str):
        return urlsafe_b64decode(data)