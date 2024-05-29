import unittest
import requests
from unittest.mock import patch, MagicMock

from mozaik_obelisk import MozaikObelisk 

class MozaikObeliskTests(unittest.TestCase):
    def setUp(self):
        with patch('mozaik_obelisk.MozaikObelisk.request_jwt_token', return_value="mocked_token"):
            self.mozaik = MozaikObelisk('http://127.0.0.1', "id", "secret")

    @patch('mozaik_obelisk.requests.post')
    def test_get_data_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'user_data': [1,2]}
        mock_post.return_value = mock_response

        data = self.mozaik.get_data('a2aad3bb-8997-4384-84dd-d800b5587997', 'user_id', [1,2])

        self.assertEqual(data, [1,2])

    @patch('mozaik_obelisk.requests.post')
    def test_get_data_failure(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response

        # In this test case, we expect a RequestException to be raised
        with self.assertRaises(requests.RequestException):
            self.mozaik.get_data('a2aad3bb-8997-4384-84dd-d800b5587997', 'user_id', 'index1')

    @patch('mozaik_obelisk.requests.get')
    def test_get_keys_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'automorphism_key': '01',
            'multiplication_key': '02',
            'addition_key': '03',
            'bootstrap_key': '04'
        }
        mock_get.return_value = mock_response

        keys = self.mozaik.get_keys('analysis_id')

        expected_keys = {
            'automorphism_key': b'\x01',
            'multiplication_key': b'\x02',
            'addition_key': b'\x03',
            'bootstrap_key': b'\x04'
        }
        self.assertEqual(keys, expected_keys)

    @patch('mozaik_obelisk.requests.get')
    def test_get_keys_failure(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        # In this test case, we expect a RequestException to be raised
        with self.assertRaises(requests.RequestException):
            self.mozaik.get_keys('analysis_id')

    @patch('mozaik_obelisk.requests.post')
    def test_store_result_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_post.return_value = mock_response

        # Call the method under test
        self.mozaik.store_result('a2aad3bb-8997-4384-84dd-d800b5587997', 'user_id', 'result_data')

        # Assert that the requests.post method was called with the correct arguments
        mock_post.assert_called_once_with(
            'http://127.0.0.1/analysis/result/a2aad3bb-8997-4384-84dd-d800b5587997',
            json={'user_id': 'user_id', 'result': 'result_data'},
            headers={'authorization': 'mocked_token'}
        )

    @patch('mozaik_obelisk.requests.post')
    def test_store_result_failure(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        # Call the method under test
        with self.assertRaises(requests.RequestException):
            self.mozaik.store_result('a2aad3bb-8997-4384-84dd-d800b5587997', 'user_id', 'result_data')

        # Assert that the requests.post method was called with the correct arguments
        mock_post.assert_called_once_with(
            'http://127.0.0.1/analysis/result/a2aad3bb-8997-4384-84dd-d800b5587997',
            json={'user_id': 'user_id', 'result': 'result_data'},
            headers={'authorization': 'mocked_token'}
        )


if __name__ == '__main__':
    unittest.main()
