import unittest
from unittest.mock import patch

from analysis_app import AnalysisApp

class AnalysisAppTests(unittest.TestCase):
    def setUp(self):
        with patch('mozaik_obelisk.MozaikObelisk.request_jwt_token', return_value="mocked_token"):
            with patch('analysis_app.TaskManager') as MockTaskManager:
                # Mocking the process_requests method of TaskManager with a no-op function
                MockTaskManager.return_value.process_requests = None
                # Create the AnalysisApp instance
                self.app = AnalysisApp('server0.toml')
                self.client = self.app.app.test_client()
                # self.app.start_background_thread()

    def tearDown(self):
        self.app.db.delete_database()
        del self.app
        del self.client 

    def test_analyse_route(self):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        with self.app.app.test_request_context('/analyse/', method='POST', headers=headers):
            data={'analysis_id': '01HQJRGMVHY51W7ZV8S2TXRQ7N', 'user_id': '01HQJRH8N3ZEXH3HX7QD56FH0W', 'data_index': [1, 2], 'analysis_type': 'Heartbeat-Demo-1'}
            response = self.client.post('/analyse/', json=data, headers=headers)
            self.assertEqual(response.status_code, 201)
            self.assertTrue(b"Request added to the queue" in response.data)

    def test_analyse_route_invalid_id(self):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        with self.app.app.test_request_context('/analyse/', method='POST', headers=headers):
            data={'analysis_id': 'invalid_id', 'user_id': '01HQJRH8N3ZEXH3HX7QD56FH0W', 'data_index': [1, 2], 'analysis_type': 'Heartbeat-Demo-1'}
            response = self.client.post('/analyse/', json=data, headers=headers)
            self.assertEqual(response.status_code, 400)
            self.assertTrue(b"Invalid analysis_id" in response.data)

    def test_get_analysis_status_route(self):
        self.app.db.create_entry('01HQJRFE0352Y5Y98VFTHEBS0X')
        self.app.db.set_status('01HQJRFE0352Y5Y98VFTHEBS0X', 'Completed')
        response = self.client.get('/status/01HQJRFE0352Y5Y98VFTHEBS0X')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'"type":"COMPLETED"' in response.data)

    def test_get_analysis_status_route(self):
        self.app.db.create_entry('01HQJRFE0352Y5Y98VFTHEBS0X')
        self.app.db.set_status('01HQJRFE0352Y5Y98VFTHEBS0X', 'Sent 1 out of 2')
        response = self.client.get('/status/01HQJRFE0352Y5Y98VFTHEBS0X')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'"type":"RUNNING"' in response.data)

    def test_get_analysis_status_route_unknown_id(self):
        response = self.client.get('/status/01HQJRGC0ZJ2Z63JZPYSQ3SRSF')
        self.assertEqual(response.status_code, 400)
        self.assertTrue(b"The analysis ID is unknown" in response.data)


if __name__ == '__main__':
    unittest.main()
