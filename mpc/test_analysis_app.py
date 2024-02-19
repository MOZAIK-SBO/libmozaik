import unittest
from unittest.mock import patch
from analysis_app import AnalysisApp  

class AnalysisAppTests(unittest.TestCase):
    def setUp(self):
        with patch('analysis_app.TaskManager') as MockTaskManager:
            # Mocking the process_requests method of TaskManager with a no-op function
            MockTaskManager.return_value.process_requests = None
            # Create the AnalysisApp instance
            self.app = AnalysisApp('server0.toml')
            self.client = self.app.app.test_client()
            self.app.start_background_thread()

    def tearDown(self):
        self.app.db.delete_database()
        del self.app
        del self.client 

    def test_analyse_route(self):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        with self.app.app.test_request_context('/analyse/', method='POST', headers=headers):
            data={'analysis_id': 'a5bfd420-545d-4d33-8a7a-7f37a1a3ced5', 'user_id': 'user', 'data_index': [1, 2], 'analysis_type': 'Heartbeat-Demo-1'}
            response = self.client.post('/analyse/', json=data, headers=headers)
            self.assertEqual(response.status_code, 201)
            self.assertTrue(b"Request added to the queue" in response.data)

    def test_analyse_route_invalid_id(self):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        with self.app.app.test_request_context('/analyse/', method='POST', headers=headers):
            data={'analysis_id': 'invalid_id', 'user_id': 'user', 'data_index': [1, 2], 'analysis_type': 'Heartbeat-Demo-1'}
            response = self.client.post('/analyse/', json=data, headers=headers)
            self.assertEqual(response.status_code, 400)
            self.assertTrue(b"Invalid analysis_id/user_id" in response.data)

    def test_get_analysis_status_route(self):
        self.app.db.create_entry('b999cbbb-2a4a-4f01-984c-26e76630e75c')
        self.app.db.set_status('b999cbbb-2a4a-4f01-984c-26e76630e75c', 'Sent')
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        with self.app.app.test_request_context('/status', method='GET', headers=headers):
            data={'analysis_id': 'b999cbbb-2a4a-4f01-984c-26e76630e75c'}
            response = self.client.get('/status', json=data, headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(b'"type":"COMPLETED"' in response.data)

    def test_get_analysis_status_route_unknown_id(self):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        with self.app.app.test_request_context('/status', method='GET', headers=headers):
            data={'analysis_id': '4ea15392-4658-4561-8db4-cf8d699b0eb2'}
            response = self.client.get('/status', json=data, headers=headers)
            self.assertEqual(response.status_code, 400)
            self.assertTrue(b"The analysis ID is unknown" in response.data)


if __name__ == '__main__':
    unittest.main()
