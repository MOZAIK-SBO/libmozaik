import unittest
from unittest.mock import patch, MagicMock
from mozaik_obelisk import MozaikObelisk 

class MozaikObeliskTests(unittest.TestCase):
    def setUp(self):
        self.mozaik = MozaikObelisk('127.0.0.1')

    @patch('mozaik_obelisk.requests.get')
    def test_get_data_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'user_data': [1,2]}
        mock_get.return_value = mock_response

        status, data = self.mozaik.get_data('a2aad3bb-8997-4384-84dd-d800b5587997', [1,2])

        self.assertEqual(status, "OK")
        self.assertEqual(data, [1,2])

    @patch('mozaik_obelisk.requests.get')
    def test_get_data_failure(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        status, response = self.mozaik.get_data('a2aad3bb-8997-4384-84dd-d800b5587997', 'index1')

        self.assertEqual(status, "Error")
        self.assertEqual(response.status_code, 404)

    @patch('mozaik_obelisk.requests.get')
    def test_get_key_share_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'key_share': 123456789}
        mock_get.return_value = mock_response

        status, key_share = self.mozaik.get_key_share('a2aad3bb-8997-4384-84dd-d800b5587997')

        self.assertEqual(status, "OK")
        self.assertEqual(key_share, 123456789)

    @patch('mozaik_obelisk.requests.get')
    def test_get_key_share_failure(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        status, response = self.mozaik.get_key_share('a2aad3bb-8997-4384-84dd-d800b5587997')

        self.assertEqual(status, "Error")
        self.assertEqual(response.status_code, 500)

    @patch('mozaik_obelisk.requests.post')
    def test_store_result_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'message': 'Result stored successfully'}
        mock_post.return_value = mock_response

        status, response = self.mozaik.store_result('a2aad3bb-8997-4384-84dd-d800b5587997', 'a2aad3bb-8997-4384-84dd-d800b5587997', [1,2])

        self.assertEqual(status, "OK")
        self.assertEqual(response['message'], 'Result stored successfully')

    @patch('mozaik_obelisk.requests.post')
    def test_store_result_failure(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        status, response = self.mozaik.store_result('a2aad3bb-8997-4384-84dd-d800b5587997', 'a2aad3bb-8997-4384-84dd-d800b5587997', [1,2])

        self.assertEqual(status, "Error")
        self.assertEqual(response.status_code, 500)


if __name__ == '__main__':
    unittest.main()
