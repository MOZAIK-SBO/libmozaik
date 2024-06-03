import os
import sys
import time
import unittest
from unittest import mock

from server import FHEServer
from base64 import urlsafe_b64encode

def make_key_dict(*args):
    keys = {}
    keys["automorphism_key"] = open("/home/Leonard/Documents/libmozaik/fhe/SERVER/test_assets/automorphism_key","rb").read()
    keys["multiplication_key"] = open("/home/Leonard/Documents/libmozaik/fhe/SERVER/test_assets/multiplication_key","rb").read()
    keys["crypto_context"] = open("/home/Leonard/Documents/libmozaik/fhe/SERVER/test_assets/crypto_context","rb").read()

    keys["automorphism_key"] = urlsafe_b64encode(keys["automorphism_key"]).decode()
    keys["multiplication_key"] = urlsafe_b64encode(keys["multiplication_key"]).decode()
    keys["crypto_context"] = urlsafe_b64encode(keys["crypto_context"]).decode()

    return keys

def make_ct(*args):
    return urlsafe_b64encode(open("/home/Leonard/Documents/libmozaik/fhe/SERVER/test_assets/test.ct.enc","rb").read()).decode()

def store_result_fake(*args):
    with open("logfile","w") as F:
        F.writelines(list(map(str, args)))

class TestFHEServer(unittest.TestCase):

    def setUp(self):
        # Create necessary directories
        self.base_path = "/home/Leonard/Documents/libmozaik/fhe/SERVER/tmp/"

        # Mock MozaikObelisk and configure it to return expected values
        self.mozaik_obelisk_patcher = mock.patch('server.MozaikObelisk')
        self.mock_mozaik_obelisk_class = self.mozaik_obelisk_patcher.start()
        self.mock_mozaik_obelisk_instance = self.mock_mozaik_obelisk_class.return_value
        self.mock_mozaik_obelisk_instance.get_data.return_value = make_ct()
        self.mock_mozaik_obelisk_instance.get_keys.return_value = make_key_dict()
        self.mock_mozaik_obelisk_instance.store_result.side_effect = store_result_fake

        self.key_names = ["automorphism_key","multiplication_key","crypto_context"]

        # Initialize the FHEServer
        self.server = FHEServer(base_url="http://127.0.0.1", base_path=self.base_path,
                                max_cache_size=100, max_workers=5)
        self.server.setup()

    def tearDown(self):
        self.mozaik_obelisk_patcher.stop()


    def test_create_analysis_job(self):

        with self.server.flask_server.test_client() as client:
            data = {
                'analysis_id': '123',
                'user_id': '456',
                'data_index': [1],
                'analysis_type': 'Heartbeat-Demo-1'
            }
            response = client.post('/analyse/', json=data)

            time.sleep(1)

            self.assertEqual(response.status_code, 201)
            self.assertIn("Request added to the queue", response.get_data(as_text=True))

            while True:
                stat = client.get("/status/123")
                stat_cont = stat.get_json()
                if stat_cont["type"] == "COMPLETED" or stat_cont["type"] == "UNKNOWN":
                    break
                time.sleep(1)
            print("OK")

if __name__ == '__main__':
    unittest.main()
