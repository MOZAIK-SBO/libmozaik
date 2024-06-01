import os
import time
import unittest
from unittest import mock
from unittest.mock import patch
from flask import json
from server import FHEServer

def make_key_dict(*args):
    keys = {}
    keys["automorphism_key"] = open("/home/leonard/PhD/libmozaik/fhe/build2/test_keys/automorphism_key").read()
    keys["multiplication_key"] = open("/home/leonard/PhD/libmozaik/fhe/build2/test_keys/mult_key").read()
    keys["addition_key"] = open("/home/leonard/PhD/libmozaik/fhe/build2/test_keys/sum_key").read()
    keys["bootstrap_key"] = open("/home/leonard/PhD/libmozaik/fhe/build2/test_keys/public_key").read()
    return keys

def make_ct(*args):
    return open("/home/leonard/PhD/libmozaik/fhe/build2/data.ct").read()

class TestFHEServer(unittest.TestCase):

    def setUp(self):
        # Create necessary directories
        self.base_path = "./"
        if not os.path.exists(self.base_path):
            os.makedirs(self.base_path)

        # Mock MozaikObelisk and configure it to return expected values
        self.mozaik_obelisk_patcher = mock.patch('server.MozaikObelisk')
        self.mock_mozaik_obelisk_class = self.mozaik_obelisk_patcher.start()
        self.mock_mozaik_obelisk_instance = self.mock_mozaik_obelisk_class.return_value
        self.mock_mozaik_obelisk_instance.get_data.return_value = make_ct()
        self.mock_mozaik_obelisk_instance.get_keys.return_value = make_key_dict()
        self.mock_mozaik_obelisk_instance.store_result.return_value = None

        self.key_names = ["automorphism_key","sum_key","mult_key","public_key"]

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
                'data_index': [1, 2, 3],
                'analysis_type': 'Heartbeat-Demo-1'
            }
            response = client.post('/analyse/', json=data)

            self.assertEqual(response.status_code, 201)
            self.assertIn("Request added to the queue", response.get_data(as_text=True))

            time.sleep(1)

            resp = response.get_json()
            self.server.current_thread.join()

            # Assert the behavior of res
            # self.assertEqual(self.server.res.status, 'SUCCESS')
            self.assertEqual(resp["status"], "Request added to the queue")


if __name__ == '__main__':
    unittest.main()
