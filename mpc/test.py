# System packages
import os
import unittest
import json
import secrets
import subprocess
import base64

from pathlib import Path
from math import log2, ceil
from datetime import datetime
from typing import Dict, Tuple
from threading import Thread

# Custom or other packages
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

from key_share import MpcPartyKeys, decrypt_key_share, prepare_params_for_dist_enc
from rep3aes import Rep3AesConfig, dist_enc, dist_dec

class TestDecryptKeyShare(unittest.TestCase):
    @staticmethod
    def get_config(party_index):
        party_keys = ['tls_certs/server1.crt', 'tls_certs/server2.crt', 'tls_certs/server3.crt']
        return {
            "server_key": f'tls_certs/server{party_index+1}.key',
            "server_cert": f'tls_certs/server{party_index+1}.crt',
            "party_index": party_index,
            "party_certs": party_keys
        }

    ciphertexts = [
        bytes.fromhex('8ca86d5cf34aaf3f271f758df5a29298b861ebc0f5cd9b3b41290b466541024e9cce3407e6d7d5fa9ab9e9e09150393e27ae241da61e51beccf2a86d663b89acad66cd6ec9b8325d8067f560e034987421298efdf5d5f6740ef5ebeb1b86312edd66dc7bccc04fac94d99912a250bb9fe6a208586f2dc30bcf81b8fa910faee7153974f8c07cc8f9bda2f265c08687b888a1905253d3274089cb857a8860809bc75d839f58c3e3b720a515105190181b5b350c97caa57f2e0126bb8452709f27c0b5d91f29e8f822631e0911de4b6d51b5e7848d74aa393c51899d91fcaf1eb60e95771bd9066d09cfdaafdee6c4bd0215c7aa5afa560d3028c50640b904716b'),
        bytes.fromhex('1770ee77177e6591020780779d07e890f97364efaa854a5f21e035fd9c5cd1ee019164723bb837ffe2311993166d78e21ab22fba8a179abe618aecfcf77289f6814769906f61ca46eaab9159e959d7a4d9abfb06810f326f4f37b234f08c1632e1e563ebe3730af948d7f0b37b7c6dc1006c1c4db8e9bdbe20a7fd648a2ff5df1e1f1d7e106fb99ff6611fc30ec55587ca58001804e0a15d126d7e80f9fd0249590ce11ae44abbabec0d58fdc6d45e6378ecca7c548ce78247b32b81a84578b8d58b8d2cd2b4f8555e3985d1e887f4de637e56f861b35a30297ce924a3e7389581537e7895a14eab9f106a5afcb62901eaf90cfb0e107aff5ad9711df5e09162'),
        bytes.fromhex('7c372f33db0d740f150f0827851c5d66f3477eb817b139315e06fe6cb8ce312433bea5642548e50f07be3422f274255960fdcf8ff576a78df523668c720e960489f8f2f325454e35633bda81a8e920deb4639d8e8a55e099b164d9d215d6bc241fb2542ecb985b73f9cb6abfbdc4032978e5da5f44331415be9ab239738282615aedc1729edb4736e05792d6237843ad00cde81f66b3e645cf345007f8140bf5cd658756332fe05ffabeae1673d71e6d8a00dcb859dc029c0adfca4e724e7b2ae2a1229127de203d03816135826263683b14ac1c4d954ac07f94d2273785474a68014bed61bf5b23b9c344a52cad4af543a1978d3dca6ebab36f2faf26b5a01a')
    ]
    expected_key = bytes.fromhex('12233445566778899aabbccddeeff001')

    def test_correct_decryption(self):
        shares = list()
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        data_indices = [1706094000, 1706094001, 1706094002, 1706094003, 1706094004, 1706094005, 1706094006, 1706094007, 1706094008, 1706094009]
        for i in range(3):
            keys = MpcPartyKeys(TestDecryptKeyShare.get_config(i))
            ct = TestDecryptKeyShare.ciphertexts[i]
            key_share = decrypt_key_share(keys, user_id, "AES-GCM-128", data_indices, analysis_type, ct)
            assert key_share != None
            shares.append(key_share)
        
        assert all(len(s) == 16 for s in shares)
        # reconstruct and check
        computed_key = bytearray(16)
        for i in range(16):
            computed_key[i] = shares[0][i] ^ shares[1][i] ^ shares[2][i]
        self.assertEqual(computed_key, TestDecryptKeyShare.expected_key, msg="Computed key does not match expected key")

    def test_params_dist_enc(self):
        keys = MpcPartyKeys(TestDecryptKeyShare.get_config(0))
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        computation_id = "28341f07-286a-4761-8fde-220b7be3d4cc"
        (nonce, ad) = prepare_params_for_dist_enc(keys, user_id, computation_id, analysis_type)
        print(f'Nonce: {nonce.hex()}')
        # the (plaintext) prediction is a vector of 5 64-bit values in little endian
        result = [6149648890722733960, 3187258121416518661, 3371553381890320898, 1292927509834657361, 1216049165532225112]
        # as bytes
        result_bytes = bytearray(len(result) * 8)
        for (i, res) in enumerate(result):
            for j in range(8):
                result_bytes[8*i+j] = (res >> 8*j) & 0xff
        
        instance = AES.new(key=TestDecryptKeyShare.expected_key, mode=AES.MODE_GCM, nonce=nonce)
        instance.update(ad)
        ct, tag = instance.encrypt_and_digest(result_bytes)

        print(f'M: {result_bytes.hex()}')
        print(f'CT: {ct.hex()}')
        print(f'Tag: {tag.hex()}')
        
    def test_aes_gcm_testvectors(self):
        key = bytes.fromhex("8ca86d5cf34aaf3f271f758df5a29298")
        nonce = bytes.fromhex("18a04c8f66bdec6a74513af6")
        instance = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
        message = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct, tag = instance.encrypt_and_digest(message)
        print(f'ct: {ct.hex()}')
        print(f'tag: {tag.hex()}')


class TestRep3Aes(unittest.TestCase):
    @classmethod
    def setUp(cls):
        bin_path = Path('rep3aes/target/release/rep3-aes')
        # run cargo to compile Rep3Aes
        try:
            subprocess.run(['cargo', 'build', '--release', '--bin', 'rep3-aes'], cwd='./rep3aes/', check=True, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            # when rust is installed via rustup, it is often placed in the home directory which is not always
            # part of PATH, so we need to add it before rebuilding
            import sys
            home = Path.home()
            possible_paths = [home / ".cargo/bin"]
            possible_paths_str = ":".join(str(pp.absolute()) for pp in possible_paths)
            os.environ["PATH"] = os.environ["PATH"] + ":" + possible_paths_str
            subprocess.run(['cargo', 'build', '--release', '--bin', 'rep3-aes'], cwd='./rep3aes/', check=True, stderr=subprocess.DEVNULL)

        cls.rep3aes_bin = str(bin_path)

    @staticmethod
    def run_dist_enc(return_val, party, path_to_bin, key_share, message_share, user_id, analysis_type, computation_id):
        if party in [0,1,2]:
            config = f'rep3aes/p{party+1}.toml'
        else:
            assert False
        rep3aes_config = Rep3AesConfig(config, path_to_bin)
        keys = MpcPartyKeys(TestDecryptKeyShare.get_config(party))
        
        ct = dist_enc(rep3aes_config, keys, user_id, computation_id, analysis_type, key_share, message_share)
        return_val[party] = ct

    @staticmethod
    def secret_share(data):
        r1 = secrets.token_bytes(len(data))
        r2 = secrets.token_bytes(len(data))
        r3 = bytearray(len(data))
        for i in range(len(data)):
            r3[i] = data[i] ^ r1[i] ^ r2[i]
        return r1, r2, r3

    @staticmethod	
    def secret_share_ring(data):
        share1 = list()
        share2 = list()
        share3 = list()
        for d in data:
            r1 = secrets.randbelow(2**64)
            r2 = secrets.randbelow(2**64)
            r3 = (d - r1 - r2) % 2**64
            share1.append((r1, r2))
            share2.append((r2, r3))
            share3.append((r3, r1))
        return (share1, share2, share3)

    @staticmethod
    def encode_ring_elements(elements):
        result_bytes = bytearray(len(elements) * 8)
        for (i, res) in enumerate(elements):
            for j in range(8):
                result_bytes[8*i+j] = (res >> 8*j) & 0xff
        return result_bytes

    def test_dist_enc(self):
        # the (plaintext) prediction is a vector of 5 64-bit values in little endian
        result = [6149648890722733960, 3187258121416518661, 3371553381890320898, 1292927509834657361, 1216049165532225112]
        # as bytes
        result_bytes = TestRep3Aes.encode_ring_elements(result)

        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        computation_id = "28341f07-286a-4761-8fde-220b7be3d4cc"

        # create key and message shares
        k1, k2, k3 = TestRep3Aes.secret_share(TestDecryptKeyShare.expected_key)
        m1, m2, m3 = TestRep3Aes.secret_share_ring(result)

        return_dict = dict()

        t1 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 0, self.rep3aes_bin, k1, m1, user_id, analysis_type, computation_id])
        t2 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 1, self.rep3aes_bin, k2, m2, user_id, analysis_type, computation_id])
        t3 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 2, self.rep3aes_bin, k3, m3, user_id, analysis_type, computation_id])

        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()

        (nonce, ad) = prepare_params_for_dist_enc(MpcPartyKeys(TestDecryptKeyShare.get_config(0)), user_id, computation_id, analysis_type)
        instance = AES.new(key=TestDecryptKeyShare.expected_key, mode=AES.MODE_GCM, nonce=nonce)
        instance.update(ad)
        expected_ct, expected_tag = instance.encrypt_and_digest(result_bytes)

        # collect return values and check the ciphertext
        cts = [return_dict[i] for i in range(3)]
        for i, ct in enumerate(cts):
            self.assertEqual(ct.hex(), expected_ct.hex() + expected_tag.hex(), msg=f"Mismatch for the {i}-th ciphertext")

    @staticmethod
    def run_dist_dec(return_val, party, path_to_bin, key_share, ct, user_id):
        if party in [0, 1, 2]:
            config = f'rep3aes/p{party+1}.toml'
        else:
            assert False
        rep3aes_config = Rep3AesConfig(config, path_to_bin)
        
        message_share = dist_dec(rep3aes_config, user_id, key_share, ct)
        return_val[party] =  message_share

    def test_dist_dec(self):
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        # create key shares
        k1, k2, k3 = TestRep3Aes.secret_share(TestDecryptKeyShare.expected_key)

        # create a message of 187 64-bit values in little endian
        ring_message = [secrets.randbelow(2**64) for _ in range(187)]
        message = TestRep3Aes.encode_ring_elements(ring_message)
        nonce = bytes.fromhex('157316abe528fe29d4716781')
        ad = bytes(user_id, encoding='utf-8') + nonce
        instance = AES.new(key=TestDecryptKeyShare.expected_key, mode=AES.MODE_GCM, nonce=nonce)
        instance.update(ad)
        ct, tag = instance.encrypt_and_digest(message)
        final_ct = nonce + ct + tag

        return_dict = dict()
        t1 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 0, self.rep3aes_bin, k1, final_ct, user_id])
        t2 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 1, self.rep3aes_bin, k2, final_ct, user_id])
        t3 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 2, self.rep3aes_bin, k3, final_ct, user_id])

        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()

        # reconstruct message shares
        m1 = return_dict[0]
        m2 = return_dict[1]
        m3 = return_dict[2]
        assert len(m1) == 187
        assert len(m2) == 187
        assert len(m3) == 187

        for i in range(187):
            # check consistent
            assert len(m1[i]) == 2 and len(m2[i]) == 2 and len(m3[i]) == 2
            assert m1[i][0] == m3[i][1]
            assert m1[i][1] == m2[i][0]
            assert m2[i][1] == m3[i][0]
            self.assertEqual(ring_message[i], ( m1[i][0] + m2[i][0] + m3[i][0]) % 2**64, msg="Reconstructed message did not match expected message.")

class IntegrationTest(unittest.TestCase):
    __slots__ = ["opts_dict", "firefox_options", "firefox_driver", "rep3aes_bin"]

    @classmethod
    def setUp(cls):

        # Set up Selenium
        cls.opts_dict = {
            "general.warnOnAboutConfig": False,
            "browser.aboutConfig.showWarning": False,
            "security.fileuri.strict_origin_policy": False
        }

        cls.firefox_options = Options()
        cls.firefox_options.add_argument("--headless")
        cls.firefox_options.add_argument('window-size=1920x1080')

        firefox_profile = webdriver.FirefoxProfile()
        for key, value in cls.opts_dict.items():
            firefox_profile.set_preference(key, value)
        cls.firefox_options.profile = firefox_profile
        cls.firefox_driver = webdriver.Firefox(options=cls.firefox_options)

        # Set up rep3aes
        bin_path = Path('rep3aes/target/release/rep3-aes')
        # run cargo to compile Rep3Aes
        try:
            subprocess.run(['cargo', 'build', '--release', '--bin', 'rep3-aes'], cwd='./rep3aes/', check=True, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            # when rust is installed via rustup, it is often placed in the home directory which is not always
            # part of PATH, so we need to add it before rebuilding
            import sys
            home = Path.home()
            possible_paths = [home / ".cargo/bin"]
            possible_paths_str = ":".join(str(pp.absolute()) for pp in possible_paths)
            os.environ["PATH"] = os.environ["PATH"] + ":" + possible_paths_str
            subprocess.run(['cargo', 'build', '--release', '--bin', 'rep3-aes'], cwd='./rep3aes/', check=True, stderr=subprocess.DEVNULL)

        cls.rep3aes_bin = str(bin_path)

    def test_trivial(self):
        """
        Checks whether the webdriver works and can load the glue html file
        :return:
        """
        root_file = Path("assets/integration_test_glue/integration_glue.html")
        self.assertTrue(root_file.exists())

        abs_path = root_file.absolute()
        self.firefox_driver.get("file://" + str(abs_path))
        self.assertTrue("html" in self.firefox_driver.title.lower())

    def test_createAnalysisRequestData(self):
        """
        Checks whether the key shares created by the client can be decrypted by the server side
        and checks whether the shares were set up properly
        """
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        data_idx = ["2024-01-24T12:00:00", "2024-01-24T12:00:01", "2024-01-24T12:00:02", "2024-01-24T12:00:03",
                    "2024-01-24T12:00:04", "2024-01-24T12:00:05", "2024-01-24T12:00:06", "2024-01-24T12:00:07",
                    "2024-01-24T12:00:08", "2024-01-24T12:00:09"]
        date_format = "%Y-%m-%dT%H:%M:%S"
        date_parsed = [datetime.strptime(date, date_format) for date in data_idx]
        date_timestamps = [round(date.timestamp()) for date in date_parsed]

        # normal values that are not part of the key don't need urlsafe base64 unlike the key. We love consistency :)))
        iot_key_bytes = bytes(
            [0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01])
        iot_key = base64.b64encode(iot_key_bytes).decode("ascii").rstrip("=")

        algorithm = "AES-GCM-128"
        key_path = Path("assets/integration_test_keys")
        analysis_type="Heartbeat-Demo-1"

        p1_key_path = key_path / "party_key_1.pem"
        p2_key_path = key_path / "party_key_2.pem"
        p3_key_path = key_path / "party_key_3.pem"

        key1, p1_json = self.pem_to_jwt(p1_key_path)
        key2, p2_json = self.pem_to_jwt(p2_key_path)
        key3, p3_json = self.pem_to_jwt(p3_key_path)

        c1, c2, c3 = self.createAnalysisRequestHook(user_id, iot_key, algorithm, p1_json, p2_json, p3_json, analysis_type, data_idx)

        ciphertexts = [c1,c2,c3]
        shares = []
        for i in range(3):
            keys = MpcPartyKeys(IntegrationTest.get_config(i))
            ct = ciphertexts[i]
            key_share = decrypt_key_share(keys, user_id, algorithm, date_timestamps, analysis_type, ct)
            shares.append(key_share)

        result = [a ^ b ^ c for a, b, c in zip(*shares)]
        self.assertListEqual(list(result), list(iot_key_bytes))

    def test_reconstruct_result_of_dist_enc(self):
        result = [6149648890722733960, 3187258121416518661, 3371553381890320898, 1292927509834657361,
                  1216049165532225112]
        # as bytes
        result_bytes = TestRep3Aes.encode_ring_elements(result)

        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        computation_id = "28341f07-286a-4761-8fde-220b7be3d4cc"

        iot_key_bytes = bytes(
            [0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01])
        iot_key = base64.b64encode(iot_key_bytes).decode("ascii").rstrip("=")

        # create key and message shares
        k1, k2, k3 = TestRep3Aes.secret_share(iot_key_bytes)
        m1, m2, m3 = TestRep3Aes.secret_share(result_bytes)

        # tls_certs/server{party_index+1}.key
        key_path = Path("./tls_certs/")
        analysis_type="Heartbeat-Demo-1"

        p1_key_path = key_path / "server1.key"
        p2_key_path = key_path / "server2.key"
        p3_key_path = key_path / "server3.key"

        key1, p1_json = self.pem_to_jwt(p1_key_path)
        key2, p2_json = self.pem_to_jwt(p2_key_path)
        key3, p3_json = self.pem_to_jwt(p3_key_path)

        return_dict = dict()

        t1 = Thread(target=TestRep3Aes.run_dist_enc,
                    args=[return_dict, 0, self.rep3aes_bin, k1, m1, user_id, analysis_type, computation_id])
        t2 = Thread(target=TestRep3Aes.run_dist_enc,
                    args=[return_dict, 1, self.rep3aes_bin, k2, m2, user_id, analysis_type, computation_id])
        t3 = Thread(target=TestRep3Aes.run_dist_enc,
                    args=[return_dict, 2, self.rep3aes_bin, k3, m3, user_id, analysis_type, computation_id])

        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()

        for i in range(3):
            res_i = return_dict[i]
            res_i_b64 = base64.b64encode(res_i).decode("ascii").rstrip("=")
            recon_i = self.reconstructResultHook(user_id, iot_key, p1_json, p2_json, p3_json, computation_id, analysis_type, res_i_b64)
            self.assertListEqual(list(result_bytes), list(recon_i))

    def reconstructResultHook(self, user_id, iot_key,  p1_key_json, p2_key_json,
                                  p3_key_json, computation_id, analysis_type, encrypted_result) -> bytes:
        script_template = """
            window.integration.reconstructResult(
                "{uid}",
                "{iot_key}",
                {p1},
                {p2},
                {p3},
                "{computation_id}",
                "{analysis_type}",
                "{encrypted_result}"
            );
        """
        script = script_template.format(
            uid=user_id,
            iot_key=iot_key,
            p1=json.dumps(p1_key_json),
            p2=json.dumps(p2_key_json),
            p3=json.dumps(p3_key_json),
            computation_id=computation_id,
            analysis_type=analysis_type,
            encrypted_result=encrypted_result
        )

        root_file = Path("assets/integration_test_glue/integration_glue.html")
        self.assertTrue(root_file.exists())

        abs_path = root_file.absolute()
        self.firefox_driver.get("file://" + str(abs_path))

        try:
            self.firefox_driver.execute_script(script)
        except Exception as e:
            import sys
            sys.stderr.write(script)
            sys.stderr.flush()
            self.firefox_driver.close()
            self.fail(msg="Webdriver threw exception :( {}".format(e))

        self.firefox_driver.implicitly_wait(0.1)
        pt64: str = self.firefox_driver.execute_script(
            "return window.integration.results.reconstructResult;")

        # Restore correct padding
        pt64 = pt64.strip()
        pt64 += "=" * ((4 - len(pt64)) % 4)
        pt: bytes = base64.urlsafe_b64decode(pt64)

        return pt

    def createAnalysisRequestHook(self, user_id, iot_key, algorithm, p1_key_json, p2_key_json,
                                  p3_key_json, analysis_type, data_indices) -> Tuple[bytes, bytes, bytes]:
        """
        Function that calls the method of the same name in JS and recovers the (hopefully correct) outputs
        :param _: all parameters play the same role as in the JS equivalent
        :return: three encrypted shared 1 per party
        """
        script_template = """
            window.integration.createAnalysisRequestData(
                "{uid}",
                "{iot_key}",
                "{alg}",
                {p1},
                {p2},
                {p3},
                "{analysis_type}",
                {data_idx}
            );
        """

        script = script_template.format(
            uid=user_id,
            iot_key=iot_key,
            alg=algorithm,
            p1=json.dumps(p1_key_json),
            p2=json.dumps(p2_key_json),
            p3=json.dumps(p3_key_json),
            analysis_type=analysis_type,
            data_idx=data_indices
        )

        root_file = Path("assets/integration_test_glue/integration_glue.html")
        self.assertTrue(root_file.exists())

        abs_path = root_file.absolute()
        self.firefox_driver.get("file://" + str(abs_path))

        try:
            self.firefox_driver.execute_script(script)
        except Exception as e:
            import sys
            sys.stderr.write(script)
            sys.stderr.flush()
            self.firefox_driver.close()
            self.fail(msg="Webdriver threw exception :( {}".format(e))

        self.firefox_driver.implicitly_wait(0.1)

        c1_b64: str = self.firefox_driver.execute_script(
            "return window.integration.results.createAnalysisRequestData.c1;")
        c2_b64: str = self.firefox_driver.execute_script(
            "return window.integration.results.createAnalysisRequestData.c2;")
        c3_b64: str = self.firefox_driver.execute_script(
            "return window.integration.results.createAnalysisRequestData.c3;")

        # Restore correct padding
        c1_b64 = c1_b64.strip()
        c1_b64 += "=" * ((4 - len(c1_b64)) % 4)
        c1: bytes = base64.urlsafe_b64decode(c1_b64)

        c2_b64 = c2_b64.strip()
        c2_b64 += "=" * ((4 - len(c2_b64)) % 4)
        c2: bytes = base64.urlsafe_b64decode(c2_b64)

        c3_b64 = c3_b64.strip()
        c3_b64 += "=" * ((4 - len(c3_b64)) % 4)
        c3: bytes = base64.urlsafe_b64decode(c3_b64)

        return c1, c2, c3

    @staticmethod
    def pem_to_jwt(pem_path: Path) -> Tuple[RSA.RsaKey, Dict]:
        """
        Takes a Path object parses the file it points to, and returns the RSAKey object and a JWK containing the public part
        :param pem_path: the path to the PEM file
        :return: RSAKey object containing the key and a json/dict containing the public info of the key
        """
        assert pem_path.exists()

        with pem_path.open() as pem:
            pem_raw = pem.read()
            pem_parsed = RSA.import_key(pem_raw)
            e_width = ceil(log2(pem_parsed.e) / 8)
            n_width = ceil(log2(pem_parsed.n) / 8)
            e_bytes = pem_parsed.e.to_bytes(length=e_width, byteorder="big")
            n_bytes = pem_parsed.n.to_bytes(length=n_width, byteorder="big")

            e_64 = base64.urlsafe_b64encode(e_bytes).decode("ascii")
            n_64 = base64.urlsafe_b64encode(n_bytes).decode("ascii")

            # the python urlsafe bas64 is not actually url safe
            # as '=' is not stripped with breaks the crypto API in JS.
            # Yet, the crypto API is not compliant with RFC 7517, which allows "=" in the encoding...
            e_64 = e_64.rstrip("=")
            n_64 = n_64.rstrip("=")

            return pem_parsed, {
                "kty": "RSA",
                "alg": "RSA-OAEP-256",
                "kid": "integration_test_key",
                "key_ops": ["encrypt"],
                "e": e_64,
                "n": n_64,
                "ext": True
            }
    @staticmethod
    def get_config(party_index):
        party_keys = ['assets/integration_test_keys/party_key_pub_1.pem',
                      'assets/integration_test_keys/party_key_pub_2.pem',
                      'assets/integration_test_keys/party_key_pub_3.pem']
        return {
            "server_key": f'assets/integration_test_keys/party_key_{party_index+1}.pem',
            "server_cert": f'assets/integration_test_keys/party_key_pub_{party_index+1}.pem',
            "party_index": party_index,
            "party_certs": party_keys
        }


if __name__ == '__main__':

    unittest.main()
