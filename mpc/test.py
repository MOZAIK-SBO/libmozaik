# System packages
import os
import unittest
import json
import secrets
import subprocess
import base64
import threading
import traceback
import datetime
import time

from pathlib import Path
from math import log2, ceil
from datetime import datetime
from typing import Dict, Tuple
from threading import Thread

from unittest import mock

# Custom or other packages
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

from key_share import MpcPartyKeys, decrypt_key_share, decrypt_key_share_for_streaming, prepare_params_for_dist_enc
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
        bytes.fromhex('3261f3c42e7b0648b128281d882b3f7e154097a1677f30f8d650da434a9eb195b705ff3393c7b87c6ac9108f71878494cb8dc55a679ca8212122cca4cf543cda47d2d0c3ae9219465c382262b669285a95e88c1e2748d2bd5197e806c7f62225675790ddb59b6a149224f41a4c198bbb99b2f886f509da6877845c22e7989108db2faa3743836f0e2a348e38ca2f2c2c3b4cab2675f4e71527399f7096b2148465a020e5d3db52f4eae0cdc2e88b1fe0a0740d29e52be73fe6d7a4581d0b7697c16cefa2797ebb66286ed8ea522c0adca103bab6b62dbdd91dd65a99c6bb97e50f98c8d899239c7a732dccbbd353f9e7edb9599bf202c283a10540fe3750ffb7'),
        bytes.fromhex('597e4a6a55e68ec973491c0078edc098d8b00427552947cd9ace0197a9aecac46232bc41181313a07a6b6dba3283c52a2904913388fa104628ec9cd43817b152fcbe5a63ce5a05f590c58547987281fe181bedeb615175d4842a3aac659a3453c1ce1da97ca8e2eab8c67c309b08af5c7aa7a8694daf26a61b28cc6f5db09b04d28dc0afadda758daf2866a25b603ede8eb1eac8659cfdbe07ffb6a9cc8803a762d99e07c80ab7d3b0bee3331e000d8c1585c6ed0a94f12d224f449c4e40e05c4ddb0ebb0aafa3b33c0066e842146d65a346228252b5c5aef27c3802b8abebcb0336a94683ca221b4e7cb92ed0aa2baa10ee20d3bbb9b7c59d2ff5c65f6c03e9'),
        bytes.fromhex('9e747dcf88b9c56a28f76d2eee420b0d329d961db9d26071f84cead6b47b5056daa9033e2fff569761c1a17bfc63fa76f3119ce9a5856be5cd89a5afb73fc9e5b60e8aafe5358a0a2b13447002839beee8a141693433a1aaa8f005b725f4e0372f64ba307162158d2a9c458dff4b02d2c2c1fe77859b326013470f9caf61ac4e3b58e5f669c9a16c907d063186ac2929a4f3d1c2f08846b50b3a699e87f486571bd63557bff6071ce5efd8e3c5c17989f2bcaa41b2b2169a228f7aabbde9c69fd8506728e9058225b28839b4b1fdf57cf108237a1fc7ba2f4a099c3060c28195d8f027142606460b647e3d9d882984f6adafea2b59f9269853b1abd38177809e')
    ]
    expected_key = bytes.fromhex('12233445566778899aabbccddeeff001')

    ks_ciphertexts = [
        bytes.fromhex('216d22d310ab78a20c91888bdb85f23845c46a5c9b90f7e109e74a125c7be51ad41cf696f490a0b603c26ebe8602e95c62a05f186ca46e8c0598ac92872648d725739f8fcaa2deb06fd1e58cc3b25fdbcc2c66f0b21b3307d63ce78b799c9b3caad0310ecad9cd29e675e56b52e2eefcd95c9bf5209978663396cbedee39c89d3042c4655134a337b8f985a23e0880626df5b718b1bc9713173ba20b5f455809c219857bd6a97733ae88df24e3758738d7e20c726b702e96c320c5235bd9fd5519bffd9d86932c12716b7f8d9edd79a0a05a983b4184b37b90c1b6e38cea684e8083f4a1c9602dbb6662cf36d5c7489deb49b652b9a92b7d8c6ff9b68e3c694c'),
        bytes.fromhex('0df72028540b7204a78e17b895bb428c2fd70e6873887b513d1cc572045ed8b4802bdf8b29a8b966ea59431beb272b675147930094611104219c474894c649d5435c8046929d15b7c1a8d730de0e705adcd5377ca0b105474fa553ffb8583c37686db27f58a03745bfdeb0d4ff89c883f281a1e363654ae959e67aba575c00f6e74483c16b0d0420f5c30b013b282becc73eb8a02cae8f932ead17e3b333751cb2ab121d7683905fc54d21aca42b8eea7120a5afc554a80bc8c135b8f16a03cd3e15eb6eaf638523b4fc7f0eebf109187820aa7283df42d5d7e0a57c0d476ac5d90cf0d34717b8bc034886e2347d5bd7f74bd2a74b12af4ed5a2f77dd6f5210c'),
        bytes.fromhex('796dab97a3bb88f4bf8c7a58fabfff5e8c3f45ea417b57992ea5fa8c48c5724c1a1e7dd6b5fa3abb58658db39268dad55495164e2706a1a4607aac29f6cf1639356830b03a83a6231e51eeb3e01aa1ac47823bde51e1f13330580c316f7cdb1049b9996807265c32906b42b25288e2b3c174abd15f1041f0ebc7276c9c353db8af857df7129445869d44c4d92e7b831d1f5d5af86d88cf41945a2daf5fb7adde114e2e0abf29ddb6c3bbd7239ccb72748e811cb857efe0661debbc4b82380d84c3d2d5cd8a35cf1c753f9e46a3194b1124f9d0594004a91c8a2d754a14230adbe47eadc972646452be53cc8fc0f89c4e347dc2241c3c7f4393c093af3ecc60f5')
    ]
    expected_key_schedule = bytes.fromhex('12233445566778899aabbccddeeff001ccaf48589ac830d100638c1cde8c7c1daabfec453077dc9430145088ee982c95e8cec66dd8b91af9e8ad4a71063566e476fdaf02ae44b5fb46e9ff8a40dc996ee013300b4e5785f008be7a7a4862e3146a02ca5924554fa92ceb35d36489d6c78df40c1aa9a143b3854a7660e1c3a0a7231450e28ab513510fff6531ee3cc596d3b2c0ca5907d39b56f8b6aab8c4733cf93d2ba6a03af83df6c24e974e063dab')

    ks_ciphertexts_streaming = [
        bytes.fromhex('4af464e669b8a3f274a12b8b6495d086d30e48703468cf99a16b54a1f483229c17924e69fb47bdb44d1cfd560a0da9053982fe2b3e9a4fa9014782f5871dfff0ff28c5f9f41764d01efe456a6ee2871a8b630c1c612240ba137358484c0bceabde489bf6da08774b6f2fb7ef1184f7166cc4eac89044f09fbdfce1d6e0baefdff57d9aa72e1f88b5d6d777c937f032b4479d602f763ce4ba8ae01817b4793cc3430feb563f8080abdd34bf94851ba7d5ab87c7dbc318b06ba63bfa436791fda29165ce33b12be01ed9538ad54ba1f652ce30404c802b296fe8889a7e8da38437de94c94a978cad4f018b41fa3f393b853a02829aca86ae51a84d2512346ab5ef'),
        bytes.fromhex('81bfab5196589142b4c65c393075b763c7d9f6391b6fda39664adf8630e14725e80530623f9449befe7ac069daa8d65e3268192051b87b9fff7cfa8ffd3ab30367ad69d4b1feaea558e2cad47d3fc4c16180947aa824ca6b78deb94d6040c7407de794593486f326588ac86edecbfb8bcb79fd2d146975ed1dceeac4010088cd220ecc77214a94ceec7272feedacbf37aca2c5acae426b57f3d6cadff4c9faf8155967e93ec4afe7ad41e5e238097c6b77b802c831c176ce224619c442fd1334eaf411ec8cdbe152abe8cd2798f52bc9d65809dd62cb5331836b6242b2409109a44b9685c9d85d7b64799c9f6c240b0c9c97682afd43abad5b1cfd0ed53108b6'),
        bytes.fromhex('893cc0db4fadb04afe21d43b36f9d6b5ea02979c15c377cde43ac9b0f46d5952b4fc67edac2a237c53922715c52723366c07501338c05efc4e687bbc9daa63e115d3bb277b5889357990a7697ebcd2c259b75e014055ffd406dea79914bae5217e7bdc9121ddc4a43206a1b90abd194554649dc6cfdc580fed2e679311f21f36f915dab594eb3a9a556af73fa7b1a15fffdae3ad49a21a4f5224acbce545d97a1abc6c42ebe982bdd1f60d3c6d426c5943f5e38ce1d5bc496281f2e9f43a301b0707a9ac6717704f82c39d7e61f8b16a01a92540c3f42379de6863af8c7730c854141d4be7489b03ea2aa59362165ad8adf5b0e60777253df3994d18b407e916')
    ]

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

    @mock.patch('time.time', mock.MagicMock(return_value=datetime.fromisoformat('2024-01-24T19:31:15').timestamp()))
    def test_correct_decryption_ks_streaming(self):
        shares = list()
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        stream_start = int(datetime.fromisoformat('2024-01-24T12:00:00').timestamp() * 1000)
        stream_stop = int(datetime.fromisoformat('2024-01-25T12:00:00').timestamp() * 1000)
        for i in range(3):
            keys = MpcPartyKeys(TestDecryptKeyShare.get_config(i))
            ct = TestDecryptKeyShare.ks_ciphertexts_streaming[i]
            key_share = decrypt_key_share_for_streaming(keys, user_id, "AES-GCM-128", stream_start, stream_stop, analysis_type, ct)
            assert key_share != None
            shares.append(key_share)
        assert all(len(s) == 176 for s in shares)
        # reconstruct and check
        computed_keyschedule = bytearray(176)
        for i in range(176):
            computed_keyschedule[i] = shares[0][i] ^ shares[1][i] ^ shares[2][i]
        self.assertEqual(computed_keyschedule, TestDecryptKeyShare.expected_key_schedule, msg="Computed key schedule does not match expected")
    
    def test_decryption_fails_for_streaming(self):
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        analysis_type = "Heartbeat-Demo-1"
        stream_start = int(datetime.fromisoformat('2024-01-24T12:00:00').timestamp() * 1000)
        stream_stop = int(datetime.fromisoformat('2024-01-25T12:00:00').timestamp() * 1000)
        keys = MpcPartyKeys(TestDecryptKeyShare.get_config(0))
        ct = TestDecryptKeyShare.ks_ciphertexts_streaming[0]
        with self.assertRaises(Exception) as context:
            key_share = decrypt_key_share_for_streaming(keys, user_id, "AES-GCM-128", stream_start, stream_stop, analysis_type, ct)
        self.assertTrue('Integrity check of key share decryption failed (invalid time)' in str(context.exception))

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
        # all times are milliseconds since epoch
        data_idx = ["2024-01-24T12:00:00", "2024-01-24T12:00:01", "2024-01-24T12:00:02", "2024-01-24T12:00:03",
                    "2024-01-24T12:00:04", "2024-01-24T12:00:05", "2024-01-24T12:00:06", "2024-01-24T12:00:07",
                    "2024-01-24T12:00:08", "2024-01-24T12:00:09"]
        date_format = "%Y-%m-%dT%H:%M:%S"
        date_parsed = [datetime.strptime(date, date_format) for date in data_idx]
        date_timestamps = [1000*round(date.timestamp()) for date in date_parsed]

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

    def test_createAnalysisRequestDataForStreaming(self):
        """
        Checks whether the key shares created by the client can be decrypted by the server side
        and checks whether the shares were set up properly
        """
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"

        # timestamps are milliseconds since epoch

        start = 1000 * (round(time.time()) - 2*60*60*24) # streaming started two days ago
        stop = start + 5*1000*60*60*24 # streaming ends in 3 days
        
        date_format = "%Y-%m-%dT%H:%M:%S"
        start_str = datetime.fromtimestamp(start/1000.).strftime(date_format)
        stop_str = datetime.fromtimestamp(stop/1000.).strftime(date_format)

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

        c1, c2, c3 = self.createAnalysisRequestForStreamingHook(user_id, iot_key, algorithm, p1_json, p2_json, p3_json, analysis_type, start_str, stop_str)

        ciphertexts = [c1,c2,c3]
        shares = []
        for i in range(3):
            keys = MpcPartyKeys(IntegrationTest.get_config(i))
            ct = ciphertexts[i]
            key_share = decrypt_key_share_for_streaming(keys, user_id, algorithm, start, stop, analysis_type, ct)
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
            assert len(res_i) == 1
            res_i = res_i[0]
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
            assert len(res_i) == 1
            res_i = res_i[0]
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
    
    def createAnalysisRequestForStreamingHook(self, user_id, iot_key, algorithm, p1_key_json, p2_key_json,
                                  p3_key_json, analysis_type, start_str, stop_str) -> Tuple[bytes, bytes, bytes]:
        """
        Function that calls the method of the same name in JS and recovers the (hopefully correct) outputs
        :param _: all parameters play the same role as in the JS equivalent
        :return: three encrypted shared 1 per party
        """
        script_template = """
            window.integration.createAnalysisRequestDataForStreaming(
                "{uid}",
                "{iot_key}",
                "{alg}",
                {p1},
                {p2},
                {p3},
                "{analysis_type}",
                "{start}",
                "{stop}"
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
            start=start_str,
            stop=stop_str,
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
            "return window.integration.results.createAnalysisRequestDataForStreaming.c1;")
        c2_b64: str = self.block_until_nonempty(
            "return window.integration.results.createAnalysisRequestDataForStreaming.c2;")
        c3_b64: str = self.block_until_nonempty(
            "return window.integration.results.createAnalysisRequestDataForStreaming.c3;")

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
    
