import os
import struct
import tempfile
import threading
import unittest
import glob
import shutil
from unittest.mock import MagicMock, mock_open, patch

import numpy as np
from Crypto.Cipher import AES

from config import Config
from database import Database
from key_share import MpcPartyKeys, prepare_params_for_dist_enc
from rep3aes import Rep3AesConfig
from task_manager import TaskManager
from test import TestRep3Aes, exception_check

class TestTaskManager(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_app = MagicMock()
        self.mock_config = MagicMock()
        self.mock_aes_config = MagicMock()
        with patch('mozaik_obelisk.MozaikObelisk.request_jwt_token', return_value="mocked_token"):
            self.task_manager = TaskManager(self.mock_app, self.mock_db, Config('server0.toml'), Rep3AesConfig('rep3aes/p1.toml', 'rep3aes/target/release/rep3-aes-mozaik'))

    @staticmethod
    def expected_encrypted_shares(i):
        analysis_id = "01HQJRH8N3ZEXH3HX7QD56FH0W"
        user_id = "e7514b7a-9293-4c83-b733-a53e0e449635"
        analysis_type = "Heartbeat-Demo-1"
        aes_key = bytes.fromhex('0102030405060708090a0b0c0d0e0f10')
        result_bytes = bytes.fromhex('6a0000000000000046000000000000002800000000000000010000000000000027000000000000006a000000000000004600000000000000280000000000000001000000000000002700000000000000')
        (nonce, ad) = prepare_params_for_dist_enc(MpcPartyKeys(TestTaskManager.get_config(0)), user_id, analysis_id, analysis_type)
        instance = AES.new(key=aes_key, mode=AES.MODE_GCM, nonce=nonce)
        instance.update(ad)
        expected_ct, expected_tag = instance.encrypt_and_digest(result_bytes)
        return expected_ct.hex(), expected_tag.hex()
    
    @staticmethod
    def get_config(party):
        party_keys = ['tls_certs/server1.crt', 'tls_certs/server2.crt', 'tls_certs/server3.crt']
        return {
            "server_key": f'tls_certs/server{party+1}.key',
            "server_cert": f'tls_certs/server{party+1}.crt',
            "party_index": party,
            "party_certs": party_keys
        }

    @staticmethod
    def process_test(task_manager, key_share, config_index):
        analysis_id = ["01HQJRH8N3ZEXH3HX7QD56FH0W", "01HQJRH8N3ZEXH3HX7QD56FH0W"]
        user_id = ["e7514b7a-9293-4c83-b733-a53e0e449635", "e7514b7a-9293-4c83-b733-a53e0e449635"]
        analysis_type = "Heartbeat-Demo-1"
        data_index = [[1706094000000, 1706094001000], [1706094000000, 1706094001000]]  # Example data index

        # Mock the methods of MozaikObelisk class
        mock_mozaik_obelisk = MagicMock()
        mock_mozaik_obelisk.get_data.return_value = [([bytes.fromhex('1313141516171819ffffffffb6df6ec8af200ee7d53a144fdbca71d6f12ba020bcfbae63f33f67035a2e954f4e09635dad634b8cc4115ca40d27685119966c5f81914956093bc4e4ed5a24de3de5c56afbd1ad5fed24cfaac63dc5292ee686e258b231be9e8276199555f5fdea1c3ddcb7c4d0e4bb5920f6eadf26e7bfde90ae642ab9cc3f348582a89bdc0b25af357883369eba38772ee6a3f585df353e63b3a5b30ed9fcf9bb3ad53e45106d167d2c80dac1e5a750dc53e38886fa7ef71a7f47fd4e45e2224b01396209029c4d5ad51eacc2f7734a0ff20c93b20b985ae73f3a1feac745984880f40632e30f8b2db7ca4ee8863064634b4b633a6715142632094f1cbc04d57843cc4b480949116a0174d03d56e084496cc5667f2abd893e0164e38738673a5278a3b363e188413b16faf5cfa2f92a78be970b43d9a46496f4b74eca68da36fa3fd2c3cdf905dc549d18c317285c9f8f024bf867ecedc5624d9bc315c6ffdd416f8073d8b97d1b8f7815eb701fe095c3af7e020de170544d83ce8a2bc85ecab906983964e77012ec21fbbf4c179bf6a8102bacc3e4cb2eef6d790fb435b4f9558d753ff32fa208595043f6b9db0466a9886a4ebeb8ae386cfd6f5ab6da55feb95eab8106796b1e81d85c1788589857d643a8ca67dfa4c04d069ee15e91b4dcc1947791ddf68853b2914fd705279a8932a9a0efe40f1f66cd88da00ddffa93ad555d840d3ca176c76059f4cb421f2bd7dc69d707b66ea20d9e47b0ac6f419d34894ad4278fdb2f0758c9b603411914463884449645e29b4d6619764c9487476d5fd55a21e706b22f18078e136b8ad455f526f069d823d9121e9ffcb6f5633b62a32a99fbfea068ed4c56f3929e412c87d43c0f7db2e0369334d5ce84f6aad30b2236ce040d8273e2894d46038058f99ef729f9a5fc22bbe77bfd6820110abfa3ec2eb483a26b3e6dd6c250b44c191f6d5a81414259f13318e5e9077558ea7eb7c10f56f17dea73d10b68188b8131a3f52247cd43bff2288de78d5f45efe9799e6711d28fd2acc51e9735b55d1bcf72336511370ba07fd260cf26c2d8f6e3651e47203b4f708eb02d70782b730a816bd4d7752c27193a1f23126e813a665f4fb437d7ac71f546823b0c11fb23492e8e9009e4c9d35b3d33754cf135d3029eb811a9c254ebc92921f1d2a129de9d55ec0319bec532944c5e4dc78a9fb7b807ed4fecb74adf5e099acbb27d6eb090f819c8326456405d1bbca67ce91fab6fcbc7677d5db920b1cdc1c8fee178d35f8b9ae2b7a62375a9a9ded38748bfecbe9b7b64cf94d80757f985b4e96098b868b5fd1530953160b63061641bc7dcb4526c1d4555f4c64d73df13953c66c36214f3156b4c2b69201cac202faf72014be009c676c6f57d4f2d7783becaead427f853bac895ee49ecfb418ac1efa30dfa0e689e5261a0d3c5917f81767d8561b9a08d3504e76256ed2f68d4a5cb18cebc4f14c182d18461aa4c806cc58ade28c9830a14963bad839c61ef10b20094a1a13acd0ea79d7a057c2baec7af62610b1e3172a8f6f3f57d6fb7e395f9bf82b6de43c0bef4db78db5ec0c7396c84951f97e8b2bd41a2348523b32d03d64dd33a5d1f919daff3eaa06299097afc0c348118f8de8310878087c3c1dd5160a1609420ee26702fc40518264d43d2374274612bd99d5b5b58c1306ef1a3bffcec776eb5312458611804061d204c3172b718f0a4f858242be5027e484d0482faf085c7d031b00b3773b745737d5c2f8bd5f0716e351dd8539356f8b97efded988ba884f2ea528b459681d1a1c2de5f21c9262337953a2930c9a9881b1f85b020a1a30224490c26483fe2493eeed999529091872d02bc0b5b162ac3180220f984cc59624f1d5c9eeb0515d0524b1a15c720ab5eae43b8790a6b5bd1a78f4dbe959f907f41b91ca0032442d2701521ba70cf786393f2163f72a96e8c019092aac9ea12c8ef0d1bc7e450b5e0a48d34cbab22c9bf3cd077ff8e4f95c4ad96f081409a51c31c56ac346e1207e546d3df993e5676af40fe96222609bdaf7b9cf4cdbac86a3bab9ef2a7c6a63712079a853dba3a742f5ad3b4e2bc1b7c2335b6bbea101d74fdd2c928dcd4b07ec2564c833f5eab10cdc45e4'), bytes.fromhex('1313141516171819ffffffffb6df6ec8af200ee7d53a144fdbca71d6f12ba020bcfbae63f33f67035a2e954f4e09635dad634b8cc4115ca40d27685119966c5f81914956093bc4e4ed5a24de3de5c56afbd1ad5fed24cfaac63dc5292ee686e258b231be9e8276199555f5fdea1c3ddcb7c4d0e4bb5920f6eadf26e7bfde90ae642ab9cc3f348582a89bdc0b25af357883369eba38772ee6a3f585df353e63b3a5b30ed9fcf9bb3ad53e45106d167d2c80dac1e5a750dc53e38886fa7ef71a7f47fd4e45e2224b01396209029c4d5ad51eacc2f7734a0ff20c93b20b985ae73f3a1feac745984880f40632e30f8b2db7ca4ee8863064634b4b633a6715142632094f1cbc04d57843cc4b480949116a0174d03d56e084496cc5667f2abd893e0164e38738673a5278a3b363e188413b16faf5cfa2f92a78be970b43d9a46496f4b74eca68da36fa3fd2c3cdf905dc549d18c317285c9f8f024bf867ecedc5624d9bc315c6ffdd416f8073d8b97d1b8f7815eb701fe095c3af7e020de170544d83ce8a2bc85ecab906983964e77012ec21fbbf4c179bf6a8102bacc3e4cb2eef6d790fb435b4f9558d753ff32fa208595043f6b9db0466a9886a4ebeb8ae386cfd6f5ab6da55feb95eab8106796b1e81d85c1788589857d643a8ca67dfa4c04d069ee15e91b4dcc1947791ddf68853b2914fd705279a8932a9a0efe40f1f66cd88da00ddffa93ad555d840d3ca176c76059f4cb421f2bd7dc69d707b66ea20d9e47b0ac6f419d34894ad4278fdb2f0758c9b603411914463884449645e29b4d6619764c9487476d5fd55a21e706b22f18078e136b8ad455f526f069d823d9121e9ffcb6f5633b62a32a99fbfea068ed4c56f3929e412c87d43c0f7db2e0369334d5ce84f6aad30b2236ce040d8273e2894d46038058f99ef729f9a5fc22bbe77bfd6820110abfa3ec2eb483a26b3e6dd6c250b44c191f6d5a81414259f13318e5e9077558ea7eb7c10f56f17dea73d10b68188b8131a3f52247cd43bff2288de78d5f45efe9799e6711d28fd2acc51e9735b55d1bcf72336511370ba07fd260cf26c2d8f6e3651e47203b4f708eb02d70782b730a816bd4d7752c27193a1f23126e813a665f4fb437d7ac71f546823b0c11fb23492e8e9009e4c9d35b3d33754cf135d3029eb811a9c254ebc92921f1d2a129de9d55ec0319bec532944c5e4dc78a9fb7b807ed4fecb74adf5e099acbb27d6eb090f819c8326456405d1bbca67ce91fab6fcbc7677d5db920b1cdc1c8fee178d35f8b9ae2b7a62375a9a9ded38748bfecbe9b7b64cf94d80757f985b4e96098b868b5fd1530953160b63061641bc7dcb4526c1d4555f4c64d73df13953c66c36214f3156b4c2b69201cac202faf72014be009c676c6f57d4f2d7783becaead427f853bac895ee49ecfb418ac1efa30dfa0e689e5261a0d3c5917f81767d8561b9a08d3504e76256ed2f68d4a5cb18cebc4f14c182d18461aa4c806cc58ade28c9830a14963bad839c61ef10b20094a1a13acd0ea79d7a057c2baec7af62610b1e3172a8f6f3f57d6fb7e395f9bf82b6de43c0bef4db78db5ec0c7396c84951f97e8b2bd41a2348523b32d03d64dd33a5d1f919daff3eaa06299097afc0c348118f8de8310878087c3c1dd5160a1609420ee26702fc40518264d43d2374274612bd99d5b5b58c1306ef1a3bffcec776eb5312458611804061d204c3172b718f0a4f858242be5027e484d0482faf085c7d031b00b3773b745737d5c2f8bd5f0716e351dd8539356f8b97efded988ba884f2ea528b459681d1a1c2de5f21c9262337953a2930c9a9881b1f85b020a1a30224490c26483fe2493eeed999529091872d02bc0b5b162ac3180220f984cc59624f1d5c9eeb0515d0524b1a15c720ab5eae43b8790a6b5bd1a78f4dbe959f907f41b91ca0032442d2701521ba70cf786393f2163f72a96e8c019092aac9ea12c8ef0d1bc7e450b5e0a48d34cbab22c9bf3cd077ff8e4f95c4ad96f081409a51c31c56ac346e1207e546d3df993e5676af40fe96222609bdaf7b9cf4cdbac86a3bab9ef2a7c6a63712079a853dba3a742f5ad3b4e2bc1b7c2335b6bbea101d74fdd2c928dcd4b07ec2564c833f5eab10cdc45e4')]), ([bytes.fromhex('1313141516171819ffffffffb6df6ec8af200ee7d53a144fdbca71d6f12ba020bcfbae63f33f67035a2e954f4e09635dad634b8cc4115ca40d27685119966c5f81914956093bc4e4ed5a24de3de5c56afbd1ad5fed24cfaac63dc5292ee686e258b231be9e8276199555f5fdea1c3ddcb7c4d0e4bb5920f6eadf26e7bfde90ae642ab9cc3f348582a89bdc0b25af357883369eba38772ee6a3f585df353e63b3a5b30ed9fcf9bb3ad53e45106d167d2c80dac1e5a750dc53e38886fa7ef71a7f47fd4e45e2224b01396209029c4d5ad51eacc2f7734a0ff20c93b20b985ae73f3a1feac745984880f40632e30f8b2db7ca4ee8863064634b4b633a6715142632094f1cbc04d57843cc4b480949116a0174d03d56e084496cc5667f2abd893e0164e38738673a5278a3b363e188413b16faf5cfa2f92a78be970b43d9a46496f4b74eca68da36fa3fd2c3cdf905dc549d18c317285c9f8f024bf867ecedc5624d9bc315c6ffdd416f8073d8b97d1b8f7815eb701fe095c3af7e020de170544d83ce8a2bc85ecab906983964e77012ec21fbbf4c179bf6a8102bacc3e4cb2eef6d790fb435b4f9558d753ff32fa208595043f6b9db0466a9886a4ebeb8ae386cfd6f5ab6da55feb95eab8106796b1e81d85c1788589857d643a8ca67dfa4c04d069ee15e91b4dcc1947791ddf68853b2914fd705279a8932a9a0efe40f1f66cd88da00ddffa93ad555d840d3ca176c76059f4cb421f2bd7dc69d707b66ea20d9e47b0ac6f419d34894ad4278fdb2f0758c9b603411914463884449645e29b4d6619764c9487476d5fd55a21e706b22f18078e136b8ad455f526f069d823d9121e9ffcb6f5633b62a32a99fbfea068ed4c56f3929e412c87d43c0f7db2e0369334d5ce84f6aad30b2236ce040d8273e2894d46038058f99ef729f9a5fc22bbe77bfd6820110abfa3ec2eb483a26b3e6dd6c250b44c191f6d5a81414259f13318e5e9077558ea7eb7c10f56f17dea73d10b68188b8131a3f52247cd43bff2288de78d5f45efe9799e6711d28fd2acc51e9735b55d1bcf72336511370ba07fd260cf26c2d8f6e3651e47203b4f708eb02d70782b730a816bd4d7752c27193a1f23126e813a665f4fb437d7ac71f546823b0c11fb23492e8e9009e4c9d35b3d33754cf135d3029eb811a9c254ebc92921f1d2a129de9d55ec0319bec532944c5e4dc78a9fb7b807ed4fecb74adf5e099acbb27d6eb090f819c8326456405d1bbca67ce91fab6fcbc7677d5db920b1cdc1c8fee178d35f8b9ae2b7a62375a9a9ded38748bfecbe9b7b64cf94d80757f985b4e96098b868b5fd1530953160b63061641bc7dcb4526c1d4555f4c64d73df13953c66c36214f3156b4c2b69201cac202faf72014be009c676c6f57d4f2d7783becaead427f853bac895ee49ecfb418ac1efa30dfa0e689e5261a0d3c5917f81767d8561b9a08d3504e76256ed2f68d4a5cb18cebc4f14c182d18461aa4c806cc58ade28c9830a14963bad839c61ef10b20094a1a13acd0ea79d7a057c2baec7af62610b1e3172a8f6f3f57d6fb7e395f9bf82b6de43c0bef4db78db5ec0c7396c84951f97e8b2bd41a2348523b32d03d64dd33a5d1f919daff3eaa06299097afc0c348118f8de8310878087c3c1dd5160a1609420ee26702fc40518264d43d2374274612bd99d5b5b58c1306ef1a3bffcec776eb5312458611804061d204c3172b718f0a4f858242be5027e484d0482faf085c7d031b00b3773b745737d5c2f8bd5f0716e351dd8539356f8b97efded988ba884f2ea528b459681d1a1c2de5f21c9262337953a2930c9a9881b1f85b020a1a30224490c26483fe2493eeed999529091872d02bc0b5b162ac3180220f984cc59624f1d5c9eeb0515d0524b1a15c720ab5eae43b8790a6b5bd1a78f4dbe959f907f41b91ca0032442d2701521ba70cf786393f2163f72a96e8c019092aac9ea12c8ef0d1bc7e450b5e0a48d34cbab22c9bf3cd077ff8e4f95c4ad96f081409a51c31c56ac346e1207e546d3df993e5676af40fe96222609bdaf7b9cf4cdbac86a3bab9ef2a7c6a63712079a853dba3a742f5ad3b4e2bc1b7c2335b6bbea101d74fdd2c928dcd4b07ec2564c833f5eab10cdc45e4'), bytes.fromhex('1313141516171819ffffffffb6df6ec8af200ee7d53a144fdbca71d6f12ba020bcfbae63f33f67035a2e954f4e09635dad634b8cc4115ca40d27685119966c5f81914956093bc4e4ed5a24de3de5c56afbd1ad5fed24cfaac63dc5292ee686e258b231be9e8276199555f5fdea1c3ddcb7c4d0e4bb5920f6eadf26e7bfde90ae642ab9cc3f348582a89bdc0b25af357883369eba38772ee6a3f585df353e63b3a5b30ed9fcf9bb3ad53e45106d167d2c80dac1e5a750dc53e38886fa7ef71a7f47fd4e45e2224b01396209029c4d5ad51eacc2f7734a0ff20c93b20b985ae73f3a1feac745984880f40632e30f8b2db7ca4ee8863064634b4b633a6715142632094f1cbc04d57843cc4b480949116a0174d03d56e084496cc5667f2abd893e0164e38738673a5278a3b363e188413b16faf5cfa2f92a78be970b43d9a46496f4b74eca68da36fa3fd2c3cdf905dc549d18c317285c9f8f024bf867ecedc5624d9bc315c6ffdd416f8073d8b97d1b8f7815eb701fe095c3af7e020de170544d83ce8a2bc85ecab906983964e77012ec21fbbf4c179bf6a8102bacc3e4cb2eef6d790fb435b4f9558d753ff32fa208595043f6b9db0466a9886a4ebeb8ae386cfd6f5ab6da55feb95eab8106796b1e81d85c1788589857d643a8ca67dfa4c04d069ee15e91b4dcc1947791ddf68853b2914fd705279a8932a9a0efe40f1f66cd88da00ddffa93ad555d840d3ca176c76059f4cb421f2bd7dc69d707b66ea20d9e47b0ac6f419d34894ad4278fdb2f0758c9b603411914463884449645e29b4d6619764c9487476d5fd55a21e706b22f18078e136b8ad455f526f069d823d9121e9ffcb6f5633b62a32a99fbfea068ed4c56f3929e412c87d43c0f7db2e0369334d5ce84f6aad30b2236ce040d8273e2894d46038058f99ef729f9a5fc22bbe77bfd6820110abfa3ec2eb483a26b3e6dd6c250b44c191f6d5a81414259f13318e5e9077558ea7eb7c10f56f17dea73d10b68188b8131a3f52247cd43bff2288de78d5f45efe9799e6711d28fd2acc51e9735b55d1bcf72336511370ba07fd260cf26c2d8f6e3651e47203b4f708eb02d70782b730a816bd4d7752c27193a1f23126e813a665f4fb437d7ac71f546823b0c11fb23492e8e9009e4c9d35b3d33754cf135d3029eb811a9c254ebc92921f1d2a129de9d55ec0319bec532944c5e4dc78a9fb7b807ed4fecb74adf5e099acbb27d6eb090f819c8326456405d1bbca67ce91fab6fcbc7677d5db920b1cdc1c8fee178d35f8b9ae2b7a62375a9a9ded38748bfecbe9b7b64cf94d80757f985b4e96098b868b5fd1530953160b63061641bc7dcb4526c1d4555f4c64d73df13953c66c36214f3156b4c2b69201cac202faf72014be009c676c6f57d4f2d7783becaead427f853bac895ee49ecfb418ac1efa30dfa0e689e5261a0d3c5917f81767d8561b9a08d3504e76256ed2f68d4a5cb18cebc4f14c182d18461aa4c806cc58ade28c9830a14963bad839c61ef10b20094a1a13acd0ea79d7a057c2baec7af62610b1e3172a8f6f3f57d6fb7e395f9bf82b6de43c0bef4db78db5ec0c7396c84951f97e8b2bd41a2348523b32d03d64dd33a5d1f919daff3eaa06299097afc0c348118f8de8310878087c3c1dd5160a1609420ee26702fc40518264d43d2374274612bd99d5b5b58c1306ef1a3bffcec776eb5312458611804061d204c3172b718f0a4f858242be5027e484d0482faf085c7d031b00b3773b745737d5c2f8bd5f0716e351dd8539356f8b97efded988ba884f2ea528b459681d1a1c2de5f21c9262337953a2930c9a9881b1f85b020a1a30224490c26483fe2493eeed999529091872d02bc0b5b162ac3180220f984cc59624f1d5c9eeb0515d0524b1a15c720ab5eae43b8790a6b5bd1a78f4dbe959f907f41b91ca0032442d2701521ba70cf786393f2163f72a96e8c019092aac9ea12c8ef0d1bc7e450b5e0a48d34cbab22c9bf3cd077ff8e4f95c4ad96f081409a51c31c56ac346e1207e546d3df993e5676af40fe96222609bdaf7b9cf4cdbac86a3bab9ef2a7c6a63712079a853dba3a742f5ad3b4e2bc1b7c2335b6bbea101d74fdd2c928dcd4b07ec2564c833f5eab10cdc45e4')])] 
        mock_mozaik_obelisk.get_key_share.return_value = [(key_share), (key_share)]  # Mocked response for get_key_share
        # Mock the store_result method to store its arguments and return a predefined value
        def store_result_side_effect(*args, **kwargs):
            mock_mozaik_obelisk.store_result_args.append((args, kwargs))
            # return ("OK", "result_success")
        mock_mozaik_obelisk.store_result.side_effect = store_result_side_effect
        mock_mozaik_obelisk.store_result_args = []

        # Assign the mocked MozaikObelisk object to the task manager
        task_manager.mozaik_obelisk = mock_mozaik_obelisk

        for aid in analysis_id:
            task_manager.db.create_entry(aid)

        # Mock the request queue to provide predefined data
        mock_request_data = [(analysis_id, user_id, analysis_type, data_index, False, None)]  
        task_manager.request_queue.get = MagicMock(side_effect=mock_request_data)

        # Call the process_requests method
        task_manager.process_requests(test=True)

        # Retrieve the arguments passed to the store_result method
        store_result_args = mock_mozaik_obelisk.store_result_args
    
        # Retrieve the actual encrypted shares written into the database
        actual_encrypted_shares = store_result_args[0][0][2]

        assert(len(user_id) == len(analysis_id) == len(data_index))
        for i in range(len(user_id)):
            (nonce, ad) = prepare_params_for_dist_enc(MpcPartyKeys(TestTaskManager.get_config(config_index)), user_id[i], analysis_id[i], analysis_type)
                
            instance = AES.new(key=bytes.fromhex('0102030405060708090a0b0c0d0e0f10'), mode=AES.MODE_GCM, nonce=nonce)
            instance.update(ad)
            pt = instance.decrypt(bytes.fromhex(actual_encrypted_shares[i]))

            if (len(pt)-16) % 40 == 0:
                number_of_samples = int((len(pt)-16) / 40)
            else:
                raise Exception('ciphertext of wrong length')

            for i in range(number_of_samples):
                # Unpack each i-th 40 bytes into 5 unsigned 64-bit integers
                actual_shares = struct.unpack('<QQQQQ', pt[i*40:(i+1)*40])

                # Divide each integer by 2^8
                actual_prediction = [val / 2**8 for val in actual_shares]

                norm_difference = abs(np.linalg.norm(actual_prediction) - np.linalg.norm([0.414063, 0.285156, 0.152344, 0.00390625, 0.148438]))

                # Assert that the actual prediction matches the expected one
                assert norm_difference < 2e-2
        
    def test_write_shares(self):
        analysis_id = "01HQJRH8N3ZEXH3HX7QD56FH0W"
        data = [[1, 2], [3, 4], [5, 6], [7, 8]]  # Example data
        expected_header_data = b'\x1e\x00\x00\x00\x00\x00\x00\x00\x6d\x61\x6c\x69\x63\x69\x6f\x75\x73\x20\x72\x65\x70\x6c\x69\x63\x61\x74\x65\x64\x20\x5a\x32\x5e\x36\x34\x40\x00\x00\x00'
        expected_written_data = b'\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
        
        # Mock open function and file object
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            # Set the temporary file path as sharesfile
            self.task_manager.sharesfile = temp_file.name

            # Call the method
            self.task_manager.write_shares(analysis_id, data)

            # Assert that the header data and written data were correctly written to the file
            with open(temp_file.name, 'rb') as file:
                written_data = file.read()
                self.assertTrue(expected_header_data in written_data)
                self.assertTrue(expected_written_data in written_data)

    def test_append_shares(self):
        analysis_id = "01HQJRH8N3ZEXH3HX7QD56FH0W"
        data1 = [[1, 2], [3, 4], [5, 6], [7, 8], [9, 10]]  # First set of data
        data2 = [[11, 12], [13, 14], [15, 16], [17, 18]]  # Second set of data
        expected_header_data = b'\x1e\x00\x00\x00\x00\x00\x00\x00\x6d\x61\x6c\x69\x63\x69\x6f\x75\x73\x20\x72\x65\x70\x6c\x69\x63\x61\x74\x65\x64\x20\x5a\x32\x5e\x36\x34\x40\x00\x00\x00'
        # expected_written_data = b'\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x0A\x00\x00\x00\x00\x00\x00\x00\x0B\x00\x00\x00\x00\x00\x00\x00\x0C\x00\x00\x00\x00\x00\x00\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x0E\x00\x00\x00\x00\x00\x00\x00\x0F\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00'

        # Mock open function and file object
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            # Set the temporary file path as sharesfile
            self.task_manager.sharesfile = temp_file.name

            # Call the method first time with write mode (not append)
            self.task_manager.write_shares(analysis_id, data1)

            # Call the method again with append flag set to True
            self.task_manager.write_shares(analysis_id, data2, append=True)

            out = self.task_manager.read_shares(analysis_id)

            # Assert that the expected written data is present in the file
            with open(temp_file.name, 'rb') as file:
                written_data = file.read()
                self.assertTrue(expected_header_data in written_data)
                self.assertTrue([[1, 2], [3, 4], [5, 6], [7, 8], [9, 10], [11, 12], [13, 14], [15, 16], [17, 18]], out)


    def test_read_shares(self):
        analysis_id = "test_analysis_id"
        expected_result = [[2,1],[4,3],[6,5],[8,7]]

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            # Write example data to the temporary file
            temp_file.write(b'\x1e\x00\x00\x00\x00\x00\x00\x00\x6d\x61\x6c\x69\x63\x69\x6f\x75\x73\x20\x72\x65\x70\x6c\x69\x63\x61\x74\x65\x64\x20\x5a\x32\x5e\x36\x34\x40\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00')
            temp_file.flush()

            # Set the temporary file path as sharesfile
            self.task_manager.sharesfile = temp_file.name

            # Call the method
            result = self.task_manager.read_shares(analysis_id, number_of_shares=4)

            # Assert that the result matches the expected result
            self.assertEqual(result, expected_result)

    def tearDown(self):
        # Cleanup: (run_offline) Remove any directories starting with "3-" in the Player-Data folder
        for folder in glob.glob('MP-SPDZ/Player-Data/3-*'):
            if os.path.isdir(folder):
                shutil.rmtree(folder)

    def test_run_offline(self):
        # Run the offline phase
        result = self.task_manager.run_offline(distributed=False)
        
        # Check if the process returned "OK"
        self.assertEqual(result, "OK")
        
        # Verify that folders starting with "3-" are created
        created_folders = glob.glob('MP-SPDZ/Player-Data/3-*')
        self.assertTrue(len(created_folders) > 0, "No folders starting with '3-' were created.")
        

    def run_process_requests_test_helper(self, encrypted_key_shares):
        if os.path.exists('test1.db'):
            os.remove('test1.db')
        if os.path.exists('test2.db'):
            os.remove('test2.db')
        if os.path.exists('test3.db'):
            os.remove('test3.db')

        db1 = Database('test1.db')
        mock_app1 = MagicMock()

        db2 = Database('test2.db')
        mock_app2 = MagicMock()

        db3 = Database('test3.db')
        mock_app3 = MagicMock()

        with patch('mozaik_obelisk.MozaikObelisk.request_jwt_token', return_value="mocked_token"):
            task_manager1 = TaskManager(mock_app1, db1, Config('server0.toml'), Rep3AesConfig(f'rep3aes/p1.toml', 'rep3aes/target/release/rep3-aes-mozaik'))
            task_manager2 = TaskManager(mock_app2, db2, Config('server1.toml'), Rep3AesConfig(f'rep3aes/p2.toml', 'rep3aes/target/release/rep3-aes-mozaik'))
            task_manager3 = TaskManager(mock_app3, db3, Config('server2.toml'), Rep3AesConfig(f'rep3aes/p3.toml', 'rep3aes/target/release/rep3-aes-mozaik'))

        with exception_check():
            # Create threads to run the test with different configurations in parallel
            thread1 = threading.Thread(target=TestTaskManager.process_test, args=(task_manager1,encrypted_key_shares[0],0,))
            thread2 = threading.Thread(target=TestTaskManager.process_test, args=(task_manager2,encrypted_key_shares[1],1,))
            thread3 = threading.Thread(target=TestTaskManager.process_test, args=(task_manager3,encrypted_key_shares[2],2,))

            # Start the threads
            thread1.start()
            thread2.start()
            thread3.start()

            # Wait for all threads to finish
            thread1.join()
            thread2.join()
            thread3.join()
    
    def test_process_requests(self):
        # aes_key = bytes.fromhex('0102030405060708090a0b0c0d0e0f10')
        # key_shares = (bytes.fromhex('f006e3a4a7935cb8e49d3b1a0d0c4ec7'), bytes.fromhex('c0d74c17159c1172578c262c1f874496'), bytes.fromhex('31d3acb7b7094ac2ba1b163a1f850541'))
        encrypted_key_shares = (
            bytes.fromhex('89eed58c59aa9038114780320fd656fbfa0c910011b316bbb11a850fa593a39744003a1ef88f157df118c1ebdeb03e5fb94d0c30793e7b428d62eed90f66a3e17a3ed01e68d3265a5ee00c39c99fca70d1019d4a87a32620027e132220f9a779e2add185386e84b18c6888f8cfdaa6f632d3788fcf371072b38ef3305ba4668dd2c50cceb1b8b0d2ac84769bb9bac7c55d1a91d823408e2a460d345e2e8b7c6b4caa50f2aeb0ff7a3b6bb6b9769a519681455abd61ac7036efe11463cb113b483b60b15dcd5e8b70830a3d9616739f856d8f92c26b3cc458933f4b5b58711900b806601cc204efab6dfb81bc5a9b5d13b3e6cf58a3618d8e4e621428c6b0aa4a'),
            bytes.fromhex('43d6cc41273391d3077a31fd2eabb62c73951261eae9ad84dc7cd70e71a63b77f90ce3d3c7bf3bb0f92dcb6207d42d758787b97e942590de348ec9c90113b17b350943b1df2945860bcd414884be0c1d69329ea77b20d0f2d995bd9f852d0983b5a67ec1fb5ce9b30dc95b047c6d194a443d36939e3cc80f11a51631ca9537ab689210b9c90159eecb29ac6ce17ba1865b106d6242fa8471d4b01ebe78ff5b557f0c2b4ce96b33860c214f99cb66de2f058147d87392be508a3fbbefa3396371232d7e5b770518bd57af526f60dd862a88fe16df367f8b64b2bdcf3c9aa02068a1f4cb0f1b68cf5e0aaa8cccee3f66639c88161a38106e5b9d24ae7031f81a8e'),
            bytes.fromhex('c2859c9c3d5b0ee61078224dace892e0176caf33b4f7e11962ebcf79accfde11172f6af08c40854fdc4a04b252b4b6cf4bc9f1825efde8e0ddbd28028010b46755a9b0d941900d0997e3399e5c3c7553edf7bb29d050575e4ce6afb3da11c397d3d6f700a078a40d47eb8c5fc2e13245d6e56079cf2a091e0e9a005f3b43e1d64d3b750b42cf7c20e27b005f6b6b549221c89e1500b660f6c1cd4d597f8fce6b26384d14199fb4b187ecdc217385d4d808dda7883b91e7388b3077bb0958a332d1f4bb2d1f238ad52cae42f03c275125245a2fe323e12fb45df5d2fac8bfb688ea743fddafa486af0c2075812bb53251c09f143135343f4be9b273e2d249d184')
        )
        self.run_process_requests_test_helper(encrypted_key_shares)
    
    def test_process_requests_with_keyschedule(self):
        # aes_key = bytes.fromhex('0102030405060708090a0b0c0d0e0f10')
        # key_schedule = 0102030405060708090a0b0c0d0e0f10ab74c9d3ae72cedba778c5d7aa76cac791000f7f3f72c1a4980a0473327cceb4858b825cbaf943f822f3478b108f893ffe2cf79644d5b46e6626f3e576a97ada3df6a0ae792314c01f05e72569ac9dff8ca8b657f58ba297ea8e45b28322d84d5fc955bbaa42f72c40ccb29ec3ee6ad3f7cb33955d89c4b91d457627deab1cf48e578c88d3de4831ce9b3e16103022e2bcc414426f1a5c73a1816265b1b14087
        ks_share1 = bytes.fromhex('3752377e20f3541a9f81a1c22190b2a559d36809483ee93969f3273a0fd54ed779b9f5c05d82e7d8094cb21e53b167de3eb510ce0f0f846b7042e5db0d826e71e60ae71b678803cb5a8028362f923c52366cbbb0c177f4f7a786908bace5d141c57adece7eb9e0386c0a30353af53afe98764458028e2e71156842c80b9c1493363abfe663e31421c95d69df4a8100b5aa101754279163caf4f247276c0ddc21fbefe50ced8c117c01808f7759786fbc754a67109baefa900c492f7225d963bc32854514e125760acc3f4e448729f0fa40c20de01be59033d8a8cf845df19bdba2674390c5efb650ea242285fc7b6488d1636bf730c00bac7997b811060d54a5')
        ks_share2 = bytes.fromhex('1939dec4d2b007cc56f313c91899192f22aca6a89aef3423d844cb6d15739a6533013c11bc2760783e93ceb9dd2560115233ae7e1348fcb5b6f67e09f2fe6d9d615aa3c63761f644d0482a60fe5e660fcd435989623de78a2911e19a408786ee3d912f8b73b8a745306e109ab4d1015abb8cce56e2e3191de3d3cc7c96300a4cdfd2ecc49f4a116aebcb9a4845a6d499522763bf8133c3d34579def7bfeee47d333d65e19bac555d1c4a36285bbdaf44918efb7ab0de6606f71f9fc92982dae5243dc337c16aab823e6d999fc9fa4e8b5462c17dd5b7f651a1b15a7264134437a35b2cf914d37f8df14afbc5ebca6c2877a957cbc88d41707ed675be379a3e55')
        ks_share3 = bytes.fromhex('7756064b2d09df282195384966c583d2e30cfdb7141888e9f1029abef017488a4a83f5091b729de0c11e0e83dbbc3e065537da12dec3543fe5362a505b02610fd9faffc9eb8a5701bcd23f7682008a0d1e5ef0f06df97b9a619de3ff04257a2d52bc096747396c1e051796d4490f21d82b128856240bb828e1ca1cff23dba8594afe51ce8c5049a0e47d31498b88aca4e8c0d55ac8bebb5d10fc0aece5dea08c8f43906275950a1704c2226b02dc3cbc6bac514020b9784f201c246f5e1e9e0ef6d582106ad4874aae2d72c98dc2e63903846fb88f340c29d04c6a1a1b2e60b46f442b4cdd22fd9ddacd45154ee457fabb59565bba60fec4a60f1b8305ad3e7d')
        self.run_process_requests_test_helper([ks_share1, ks_share2, ks_share3])

if __name__ == '__main__':
    unittest.main()
