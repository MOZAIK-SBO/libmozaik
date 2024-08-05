# System packages
import os
import unittest
import json
import secrets
import subprocess
import base64
import threading
import traceback

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

class ExceptionHookContextManager:
    """ 
    Context manager that will raise an exception if an uncaught exception terminated a thread that is started and joined within the context.

    Usage:
    t = Thread(target=lambda: <some exception raised here>)
    with ExceptionHookContextManager():
        t.start()
        # ...
        t.join()
    # exception will be raised at this point after the context manager exited
    """

    def __init__(self):
        self.old_hook = None
        self.uncaught_exceptions = list()
    
    def __enter__(self):
        # register myself as excepthook but keep the old one around
        self.old_hook = threading.excepthook
        threading.excepthook = self.hook
    
    def hook(self, args):
        # called when an uncaught exception terminates the thread
        self.uncaught_exceptions.append((args.exc_type, args.exc_value, args.exc_traceback))
    
    def __exit__(self, *exc_args):
        # register the old hook
        threading.excepthook = self.old_hook
        del self.old_hook
        # check if there are exceptions
        if len(self.uncaught_exceptions) > 0:
            for e_type, e_value, e_traceback in self.uncaught_exceptions:
                print(f"Uncaught exception in other thread: {e_type} {e_value}")
                traceback.print_tb(e_traceback)
            del self.uncaught_exceptions # to prevent reference cycles
            raise Exception("Uncaught exception in other thread, see trace above")

def exception_check():
    """ 
    Context manager that will raise an exception if an uncaught exception terminated a thread that is started and joined within the context.

    Usage:
    t = Thread(target=lambda: <some exception raised here>)
    with exception_check():
        t.start()
        # ...
        t.join()
    # exception will be raised at this point after the context manager exited
    """
    return ExceptionHookContextManager()

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
        bytes.fromhex('80db8c887cb023517d809e5fad424221ba3ca51328a47a505a58519a03d9c19c03b861bb54e81d88227f6ca073b2c05d2a9e25f8577dcfe58ae935386ed1ae44cfb3d70ebbba482e085503d41bdd511385901df24984c86b2f551bf1bebb32be6bdd6737249502b113e7e48aece04cf6171de534d7e1cf12f1c7f914950d9f3ee1750e1749fc8ecde7595e6e7af99166ed29c0744a839dc504c666860f9f3193c660e2571f9d4b30aa82c65049811bfb529827b10766833a5734849ad54b787a11e810e9a2327f188869b8ab88b90f5472f2dc176a0fd406a005a5a0d66876138b3c4b061985c2c940effde85ac350328b6fbc2b1b157568dc92d0448004663a'),
        bytes.fromhex('66887021bb4870808989d1e4f11726ee903e6c9d46f4cac292a156fbc04dd2d394001fd70525be2a7c65da3441eed89f4336983ca7369c63cf258e0d22de7f83cdf02a9918160fcd9d72368eedd10c7f856722bb778e43518ab10a9acb19550518322a563b910b31d27de39db30101e0586dd96a6af4566900ffb022e4a4f7f21e853961a81f89ef05f21feaffad08343eadc8a1d89d22d4e4c83922b1d5932e24b2d65da9dc9df201395666a7565543ad0e9b09376f4fc55b9d888135fd6bbd463c201b0c1da64931a3b088318c8383f8db9fe2237fe2741d87a47886809a6add07227ccec9d390c63f50b7b1e932037e699c708b3e50697888064fad0f08c9'),
        bytes.fromhex('a3c47abe9b292fa962f3b2f85d25cee76a8f176b1e4b42e265cdfdab57915cddeca990964cd2c8f87474c775cd0bc7fd7ea407e56bdcbc9700bc1d33174d1e5bb032a74c71aff8d14af9792f0bd5de871e57a1823ba9b317aee3a708e5c9608d6bb6a5c0c2c0ae134efd23c741b6c0bd1c666b181a1fad8d1caae6ba559cdbabce03968999d29e1dfa7bd7302906654ad0de9523649ef412ef76eb4bf2f380dc74c9fea23c47be264ba63a3e48eb0ae5e6ef29df27d4f0fe93ead18f8a4f0d45c80b5b7e04cca65e60ee22c02fe04825be0842cd27828611b167a86e4730a6ff3cb311b2f4baaf88b218b072ea071f8c48ac3c38e3cab83526f20fb380baf4ff')
    ]
    expected_key = bytes.fromhex('12233445566778899aabbccddeeff001')

    ks_ciphertexts = [
        bytes.fromhex('47b6e2f7b24ab350d9f32e06b4161bf017021121439d8bc13abf379fd6f0c21c1ab28cd269cac4fbed90c84511ae68054ec2e640ff132e04523cb6b266e663ea420e0fae09758dbe28f1111f72cfd3334ac6e322f993eb89a2b3cabaf19c25d34df50faf99fb0bd4e1ef76a5fd16974ef6a701a308ddf5ab3c88ed796231e7f10de7cea295fd5e16804b8e0126b9f709c8b961d069d577d6dbe026430073a43146d2eadf24791b56b1bceb8e65b416b8f4e391ac2d86fe6454df3a6a5fd0cafe95dba51ebcf0b3ed920235142a85e76717127e683da8fe9ca0d96594edf6229add29c0d438802a04ff75a6b0292b81301c3e5db3241f870600577a47f5f974a0'),
        bytes.fromhex('8924a814c2c601a456485baa6c63ec24efd4dd149dc6428883c108c8d48d58a21ed43658d5e4e2152a8808aec90c4d0dbb5f3c9b948dc97fdc334fa577087c378734985260d70c1cf16c8ad7c25369a5bf1731225a2b16b8710b66523693500b7dca23fa0e592536a527e91f70c19ef4f9b556cde7394ae14bb225389d8a2fdee0d01eceeedbae8f2d787e3965acb507c7acbd386a7bcf38fbc10565d582e7c0d18c6a9ec337bc9815f727770947d877a9781909dce5ed783cb3826f554f593870158ad917da5cc3411df8f4834a01d98159a9906e44c9c26d0fc8eb1bddac33a385da65e42eebb30bc4756c59c7342fa40fb22454728d4ffb0c345e82b2ada4'),
        bytes.fromhex('930a004a895891669e83a9a312bc0e867deaf0f38cf1be8f1dea1b1ec2ae6aeaae15c7d8714c9f71c8b2ea774a079b66c4f49057d8f19e61c644901e11c3c7430aab28f4c3af9878b697d66c8ada75928ae4abf01659db4b4b14a1e50ba9fcf403c074b3157351126f53f79594cba14b98f5448e33cc7d9674c58c393a6c7bd027ed0831f9e7a43be21c18b40d46f315288e0bebbbf941c855ba265b51346e6d89fd85af7cba094d0f6869ed02c4de601ab2f29514d2b54503c68aad25b13c6ec4991e5732a9560450c7c2485acec2ea3387ac12a6d870b6c7b1395bd6dfd136945d22f4fada6c60e95e411f8d35e906314143d1d6cec4f8c8690e7ceffaaaa2')
    ]
    expected_key_schedule = bytes.fromhex('12233445566778899aabbccddeeff001ccaf48589ac830d100638c1cde8c7c1daabfec453077dc9430145088ee982c95e8cec66dd8b91af9e8ad4a71063566e476fdaf02ae44b5fb46e9ff8a40dc996ee013300b4e5785f008be7a7a4862e3146a02ca5924554fa92ceb35d36489d6c78df40c1aa9a143b3854a7660e1c3a0a7231450e28ab513510fff6531ee3cc596d3b2c0ca5907d39b56f8b6aab8c4733cf93d2ba6a03af83df6c24e974e063dab')

    def test_correct_decryption(self):
        shares = list()
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        data_indices = [1706094000000, 1706094001000, 1706094002000, 1706094003000, 1706094004000, 1706094005000, 1706094006000, 1706094007000, 1706094008000, 1706094008001]
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
    
    def test_correct_decryption_ks(self):
        shares = list()
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        data_indices = [1706094000000, 1706094001000, 1706094002000, 1706094003000, 1706094004000, 1706094005000, 1706094006000, 1706094007000, 1706094008000, 1706094008001]
        for i in range(3):
            keys = MpcPartyKeys(TestDecryptKeyShare.get_config(i))
            ct = TestDecryptKeyShare.ks_ciphertexts[i]
            key_share = decrypt_key_share(keys, user_id, "AES-GCM-128", data_indices, analysis_type, ct)
            assert key_share != None
            shares.append(key_share)
        
        assert all(len(s) == 176 for s in shares)
        # reconstruct and check
        computed_keyschedule = bytearray(176)
        for i in range(176):
            computed_keyschedule[i] = shares[0][i] ^ shares[1][i] ^ shares[2][i]
        self.assertEqual(computed_keyschedule, TestDecryptKeyShare.expected_key_schedule, msg="Computed key schedule does not match expected")

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
    @staticmethod
    def compileAndSetupRep3AES():
        """ Compiles the rep3-aes binary and returns its path """
        bin_path = Path('rep3aes/target/release/rep3-aes-mozaik')
        # run cargo to compile Rep3Aes
        env = os.environ.copy()
        env['RUSTFLAGS'] = '-C target-cpu=native'
        try:
            subprocess.run(['cargo', 'build', '--release', '--bin', 'rep3-aes-mozaik'], cwd='./rep3aes/', check=True, stderr=subprocess.DEVNULL, env=env)
        except FileNotFoundError:
            # when rust is installed via rustup, it is often placed in the home directory which is not always
            # part of PATH, so we need to add it before rebuilding
            import sys
            home = Path.home()
            possible_paths = [home / ".cargo/bin"]
            possible_paths_str = ":".join(str(pp.absolute()) for pp in possible_paths)
            os.environ["PATH"] = os.environ["PATH"] + ":" + possible_paths_str
            subprocess.run(['cargo', 'build', '--release', '--bin', 'rep3-aes-mozaik'], cwd='./rep3aes/', check=True, stderr=subprocess.DEVNULL, env=env)
        return bin_path
        

    @classmethod
    def setUpClass(cls):
        cls.rep3aes_bin = cls.compileAndSetupRep3AES()

        # run cargo to compile iot_integration
        bin_path = Path('iot_integration/target/release/iot_integration')
        try:
            subprocess.run(['cargo', 'build', '--release'], cwd='./iot_integration/', check=True, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            # when rust is installed via rustup, it is often placed in the home directory which is not always
            # part of PATH, so we need to add it before rebuilding
            import sys
            home = Path.home()
            possible_paths = [home / ".cargo/bin"]
            possible_paths_str = ":".join(str(pp.absolute()) for pp in possible_paths)
            os.environ["PATH"] = os.environ["PATH"] + ":" + possible_paths_str
            subprocess.run(['cargo', 'build', '--release'], cwd='./iot_integration/', check=True, stderr=subprocess.DEVNULL)
        cls.iot_integration_bin = str(bin_path)

    @staticmethod
    def run_dist_enc(return_val, party, path_to_bin, params):
        """
        - params: list of tuples
            - user_id: string
            - computation_id: string
            - analysis_type: string
            - key_share: bytes-like of length 16 or 176
            - message_share: list-like of 64-bit numbers in pairs (e.g. [[1,2], [3,4]])
        """
        if party in [0,1,2]:
            config = f'rep3aes/p{party+1}.toml'
        else:
            assert False
        rep3aes_config = Rep3AesConfig(config, path_to_bin)
        keys = MpcPartyKeys(TestDecryptKeyShare.get_config(party))
        
        ct = dist_enc(rep3aes_config, keys, params)
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

        t1 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 0, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k1, m1)]])
        t2 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 1, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k2, m2)]])
        t3 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 2, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k3, m3)]])

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
            assert len(ct) == 1
            ct = ct[0]
            assert ct is not None
            self.assertEqual(ct.hex(), expected_ct.hex() + expected_tag.hex(), msg=f"Mismatch for the {i}-th ciphertext")

    def test_dist_enc_ks(self):
        # the (plaintext) prediction is a vector of 5 64-bit values in little endian
        result = [6149648890722733960, 3187258121416518661, 3371553381890320898, 1292927509834657361, 1216049165532225112]
        # as bytes
        result_bytes = TestRep3Aes.encode_ring_elements(result)

        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        computation_id = "28341f07-286a-4761-8fde-220b7be3d4cc"

        # create key schedule and message shares
        k1, k2, k3 = TestRep3Aes.secret_share(TestDecryptKeyShare.expected_key_schedule)
        m1, m2, m3 = TestRep3Aes.secret_share_ring(result)

        return_dict = dict()

        t1 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 0, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k1, m1)]])
        t2 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 1, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k2, m2)]])
        t3 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 2, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k3, m3)]])

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
            assert len(ct) == 1
            ct = ct[0]
            assert ct is not None
            self.assertEqual(ct.hex(), expected_ct.hex() + expected_tag.hex(), msg=f"Mismatch for the {i}-th ciphertext")
    
    def test_dist_enc_ks_batched(self):
        BATCHSIZE = 10
        # the (plaintext) prediction is a vector of 5 64-bit values in little endian
        result = [[secrets.randbelow(2**64) for _ in range(5)] for _ in range(BATCHSIZE)]
        # as bytes
        result_bytes = [TestRep3Aes.encode_ring_elements(pred) for pred in result]

        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        computation_id = "28341f07-286a-4761-8fde-220b7be3d4cc"

        # create key schedule and message shares
        k1, k2, k3 = TestRep3Aes.secret_share(TestDecryptKeyShare.expected_key_schedule)
        message_shares = [TestRep3Aes.secret_share_ring(pred) for pred in result]
        args1 = [(user_id, computation_id, analysis_type, k1, m1) for (m1, _, _) in message_shares]
        args2 = [(user_id, computation_id, analysis_type, k2, m2) for (_, m2, _) in message_shares]
        args3 = [(user_id, computation_id, analysis_type, k3, m3) for (_, _, m3) in message_shares]

        return_dict = dict()

        t1 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 0, self.rep3aes_bin, args1])
        t2 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 1, self.rep3aes_bin, args2])
        t3 = Thread(target=TestRep3Aes.run_dist_enc, args=[return_dict, 2, self.rep3aes_bin, args3])

        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()

        expected_cts = []
        expected_tags = []
        (nonce, ad) = prepare_params_for_dist_enc(MpcPartyKeys(TestDecryptKeyShare.get_config(0)), user_id, computation_id, analysis_type)
        for data in result_bytes:
            instance = AES.new(key=TestDecryptKeyShare.expected_key, mode=AES.MODE_GCM, nonce=nonce)
            instance.update(ad)
            expected_ct, expected_tag = instance.encrypt_and_digest(data)
            expected_cts.append(expected_ct)
            expected_tags.append(expected_tag)

        # collect return values and check the ciphertext
        cts = [return_dict[i] for i in range(3)]
        for i, ct in enumerate(cts):
            assert len(ct) == BATCHSIZE
            for cti, expected_ct, expected_tag in zip(ct, expected_cts, expected_tags):
                assert cti is not None
                self.assertEqual(cti.hex(), expected_ct.hex() + expected_tag.hex(), msg=f"Mismatch for the {i}-th ciphertext")

    @staticmethod
    def run_dist_dec(return_val, party, path_to_bin, args):
        """
        args: list of (user_id, key_share, ciphertext) with
        - user_id: string
        - key_share: bytes-like of length 16 or 176
        - ciphertext: bytes-like
        """
        if party in [0, 1, 2]:
            config = f'rep3aes/p{party+1}.toml'
        else:
            assert False
        rep3aes_config = Rep3AesConfig(config, path_to_bin)
        
        message_share = dist_dec(rep3aes_config, args)
        return_val[party] =  message_share

    def run_iot_protect(self, key, nonce, user_id, message):
        result = subprocess.run([self.iot_integration_bin, '--key', str(key.hex()), '--nonce', str(nonce.hex()), '--user-id', user_id, '--message', str(message.hex())], check=True, capture_output=True)
        ct_hex = result.stdout.decode("utf-8")
        ct = bytes.fromhex(ct_hex)
        return ct

    def test_dist_dec(self):
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        # create key shares
        k1, k2, k3 = TestRep3Aes.secret_share(TestDecryptKeyShare.expected_key)

        # create a message of 187 64-bit values in little endian
        ring_message = [secrets.randbelow(2**64) for _ in range(187)]
        message = TestRep3Aes.encode_ring_elements(ring_message)
        nonce = bytes.fromhex('157316abe528fe29d4716781')
        final_ct = self.run_iot_protect(TestDecryptKeyShare.expected_key, nonce, user_id, message)

        return_dict = dict()
        t1 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 0, self.rep3aes_bin, [(user_id, k1, final_ct)]])
        t2 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 1, self.rep3aes_bin, [(user_id, k2, final_ct)]])
        t3 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 2, self.rep3aes_bin, [(user_id, k3, final_ct)]])

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
        assert len(m1) == 1
        assert len(m2) == 1
        assert len(m3) == 1
        m1 = m1[0]
        m2 = m2[0]
        m3 = m3[0]
        assert m1 is not None
        assert m2 is not None
        assert m3 is not None
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

    def test_dist_dec_with_ks(self):
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        # create key schedule shares
        k1, k2, k3 = TestRep3Aes.secret_share(TestDecryptKeyShare.expected_key_schedule)

        # create a message of 187 64-bit values in little endian
        ring_message = [secrets.randbelow(2**64) for _ in range(187)]
        message = TestRep3Aes.encode_ring_elements(ring_message)
        nonce = bytes.fromhex('157316abe528fe29d4716781')
        final_ct = self.run_iot_protect(TestDecryptKeyShare.expected_key, nonce, user_id, message)

        return_dict = dict()
        t1 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 0, self.rep3aes_bin, [(user_id, k1, final_ct)]])
        t2 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 1, self.rep3aes_bin, [(user_id, k2, final_ct)]])
        t3 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 2, self.rep3aes_bin, [(user_id, k3, final_ct)]])

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
        assert len(m1) == 1
        assert len(m2) == 1
        assert len(m3) == 1
        m1 = m1[0]
        m2 = m2[0]
        m3 = m3[0]
        assert m1 is not None
        assert m2 is not None
        assert m3 is not None
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
    
    def test_dist_dec_with_ks_batched(self):
        BATCHSIZE = 10
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        # create key schedule shares
        k1, k2, k3 = TestRep3Aes.secret_share(TestDecryptKeyShare.expected_key_schedule)

        # create a message of 187 64-bit values in little endian
        ring_message = [[secrets.randbelow(2**64) for _ in range(187)] for _ in range(BATCHSIZE)]
        message = [TestRep3Aes.encode_ring_elements(m) for m in ring_message]
        nonce = bytes.fromhex('157316abe528fe29d4716781')
        final_ct = [self.run_iot_protect(TestDecryptKeyShare.expected_key, nonce, user_id, m) for m in message]

        args1 = [(user_id, k1, ct) for ct in final_ct]
        args2 = [(user_id, k2, ct) for ct in final_ct]
        args3 = [(user_id, k3, ct) for ct in final_ct]

        return_dict = dict()
        t1 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 0, self.rep3aes_bin, args1])
        t2 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 1, self.rep3aes_bin, args2])
        t3 = Thread(target=TestRep3Aes.run_dist_dec, args=[return_dict, 2, self.rep3aes_bin, args3])

        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()

        # reconstruct message shares
        m1_batch = return_dict[0]
        m2_batch = return_dict[1]
        m3_batch = return_dict[2]

        assert len(m1_batch) == BATCHSIZE
        assert len(m2_batch) == BATCHSIZE
        assert len(m3_batch) == BATCHSIZE

        for (m1, m2, m3, expected) in zip(m1_batch, m2_batch, m3_batch, ring_message):
            assert m1 is not None
            assert m2 is not None
            assert m3 is not None

            assert len(m1) == 187
            assert len(m2) == 187
            assert len(m3) == 187

            for i in range(187):
                # check consistent
                assert len(m1[i]) == 2 and len(m2[i]) == 2 and len(m3[i]) == 2
                assert m1[i][0] == m3[i][1]
                assert m1[i][1] == m2[i][0]
                assert m2[i][1] == m3[i][0]
                self.assertEqual(expected[i], ( m1[i][0] + m2[i][0] + m3[i][0]) % 2**64, msg="Reconstructed message did not match expected message.")

class IntegrationTest(unittest.TestCase):
    __slots__ = ["opts_dict", "firefox_options", "firefox_driver", "rep3aes_bin"]

    @classmethod
    def setUpClass(cls):
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
        cls.rep3aes_bin = TestRep3Aes.compileAndSetupRep3AES()
    
    @classmethod
    def tearDownClass(cls):
        # close and quit selenium
        cls.firefox_driver.quit()

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
        self.assertListEqual(list(result), list(TestDecryptKeyShare.expected_key_schedule))

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
        m1, m2, m3 = TestRep3Aes.secret_share_ring(result)

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
                    args=[return_dict, 0, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k1, m1)]])
        t2 = Thread(target=TestRep3Aes.run_dist_enc,
                    args=[return_dict, 1, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k2, m2)]])
        t3 = Thread(target=TestRep3Aes.run_dist_enc,
                    args=[return_dict, 2, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k3, m3)]])

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
    
    def test_reconstruct_result_of_dist_enc_ks(self):
        result = [6149648890722733960, 3187258121416518661, 3371553381890320898, 1292927509834657361,
                  1216049165532225112]
        # as bytes
        result_bytes = TestRep3Aes.encode_ring_elements(result)

        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        computation_id = "28341f07-286a-4761-8fde-220b7be3d4cc"

        iot_key = base64.b64encode(TestDecryptKeyShare.expected_key).decode("ascii").rstrip("=")

        # create key shcedule and message shares
        k1, k2, k3 = TestRep3Aes.secret_share(TestDecryptKeyShare.expected_key_schedule)
        m1, m2, m3 = TestRep3Aes.secret_share_ring(result)

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
                    args=[return_dict, 0, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k1, m1)]])
        t2 = Thread(target=TestRep3Aes.run_dist_enc,
                    args=[return_dict, 1, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k2, m2)]])
        t3 = Thread(target=TestRep3Aes.run_dist_enc,
                    args=[return_dict, 2, self.rep3aes_bin, [(user_id, computation_id, analysis_type, k3, m3)]])

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

    def block_until_nonempty(self, script):
        res = self.firefox_driver.execute_script(script)
        while res == None:
            self.firefox_driver.implicitly_wait(0.1)
            res = self.firefox_driver.execute_script(script)
        return res

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

        self.firefox_driver.implicitly_wait(1)
        pt64: str = self.block_until_nonempty(
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

        self.firefox_driver.implicitly_wait(1)

        c1_b64: str = self.block_until_nonempty(
            "return window.integration.results.createAnalysisRequestData.c1;")
        c2_b64: str = self.block_until_nonempty(
            "return window.integration.results.createAnalysisRequestData.c2;")
        c3_b64: str = self.block_until_nonempty(
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
    
