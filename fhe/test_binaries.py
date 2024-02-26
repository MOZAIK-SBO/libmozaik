import unittest
import subprocess
import numpy as np
import os
import uuid
from pathlib import Path
import shutil

class FHEBinaryTests(unittest.TestCase):

    __slots__ = ["test_dir","nn_config_path"]

    @classmethod
    def setUpClass(cls):
        cls.test_dir = Path(str(uuid.uuid4()))
        cls.test_dir.mkdir()
        cls.nn_config_path = "assets/configs/default/config.json"
        env = os.environ.copy()
        env["CC"] = "/usr/bin/clang"
        env["CXX"] = "/usr/bin/clang++"
        os.chdir(str(cls.test_dir))
        subprocess.call(["cmake", ".."],env=env,stderr=subprocess.DEVNULL)
        subprocess.call(["make", "all"],env=env,stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        os.chdir("..")
        shutil.rmtree(str(cls.test_dir))

    def test_basic_keygen(self):
        subprocess.call(["./client_keygen", "fhe_key_dir", self.nn_config_path])
        expected_files = ["automorphism_key","crypto_context","crypto_config.json","mult_key","public_key","sum_key","secret_key"]
        path = Path.cwd() / "fhe_key_dir"
        for ff in expected_files:
            ff_path = path / ff
            self.assertTrue(ff_path.is_file(), str(ff_path))
    def test_basic_protect(self):

        vec = np.random.rand(180)
        path = Path.cwd()
        data_path = path / "data"
        with data_path.open("w") as f:
            f.writelines(list(map(str, vec.tolist())))

        out_file = path / str(uuid.uuid4())

        subprocess.call(["./iot_protect", "fhe_key_dir/public_key", str(data_path), str(out_file)])
        self.assertTrue(out_file.is_file(), msg=str(out_file))

if __name__ == "__main__":
    unittest.main()