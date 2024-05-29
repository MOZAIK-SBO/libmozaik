import os
import time
import unittest
from unittest import mock
from flask import json
from server import FHEServer

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
        self.mock_mozaik_obelisk_instance.get_data.return_value = 'mock_data'
        self.mock_mozaik_obelisk_instance.store_result.return_value = None

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
                'analysis_type': 'type'
            }
            response = client.post('/analyse/', json=data)

            self.assertEqual(response.status_code, 201)
            self.assertIn("Request added to the queue", response.get_data(as_text=True))

            time.sleep(1)

            # Assert the behavior of res
            self.assertEqual(self.server.res.status, 'SUCCESS')
            self.assertEqual(self.server.res.result, "good")

if __name__ == '__main__':
    unittest.main()
