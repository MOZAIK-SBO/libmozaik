import unittest
import json
from unittest.mock import MagicMock
from analysis_app import AnalysisApp  

class AnalysisAppTests(unittest.TestCase):
    def setUp(self):
        self.app = AnalysisApp('server0.toml')
        self.client = self.app.app.test_client()
        self.app.start_background_thread()

    def tearDown(self):
        del self.app
        del self.client

    def test_analyse_route(self):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        with self.app.app.test_request_context('/analyse/', method='POST', data=json.dumps({'analysis_id': 'a5bfd420-545d-4d33-8a7a-7f37a1a3ced5', 'user_id': 'user', 'data_index': [1, 2], 'analysis_type': 'type'}), headers = headers):
            response = self.client.post('/analyse/')
            print(response.request.headers)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(b"Request added to the queue" in response.data)

    def test_analyse_route_invalid_id(self):
        with self.app.app.test_request_context('/analyse/', method='POST', data=json.dumps({'analysis_id': 'invalid_id', 'user_id': 'user', 'data_index': [1, 2], 'analysis_type': 'type'}), content_type='application/json'):
            response = self.client.post('/analyse/')
            self.assertEqual(response.status_code, 400)
            self.assertTrue(b"Invalid analysis_id/user_id" in response.data)

    def test_get_analysis_status_route(self):
        mock_db = MagicMock()
        mock_db.read_entry.return_value = ('test_id', 'Completed', 'result')
        self.app.db = mock_db
        with self.app.app.test_request_context('/status', method='GET', query_string={'analysis_id': 'test_id'}):
            response = self.client.get('/status')
            self.assertEqual(response.status_code, 200)
            self.assertTrue(b'"type":"COMPLETED"' in response.data)

    def test_get_analysis_status_route_unknown_id(self):
        mock_db = MagicMock()
        mock_db.read_entry.return_value = None
        self.app.db = mock_db
        with self.app.app.test_request_context('/status', method='GET', query_string={'analysis_id': 'unknown_id'}):
            response = self.client.get('/status')
            self.assertEqual(response.status_code, 400)
            self.assertTrue(b"The analysis ID is unknown" in response.data)


if __name__ == '__main__':
    unittest.main()
