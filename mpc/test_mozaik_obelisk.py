import unittest
from unittest.mock import patch, MagicMock

from mozaik_obelisk import MozaikObelisk 
from config import ProcessException

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

        with self.assertRaises(ProcessException) as context:
            self.mozaik.get_data('a2aad3bb-8997-4384-84dd-d800b5587997', 'user_id', [1, 2])

        self.assertEqual(context.exception.code, 500)
        self.assertIn('ERROR:', context.exception.message)

    @patch('mozaik_obelisk.requests.get')
    def test_get_key_share_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'key_share': '1234567890'}
        mock_get.return_value = mock_response

        key_share = self.mozaik.get_key_share('a2aad3bb-8997-4384-84dd-d800b5587997')

        self.assertEqual(key_share, bytes.fromhex('1234567890'))

    @patch('mozaik_obelisk.requests.get')
    def test_get_key_share_failure(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        with self.assertRaises(ProcessException) as context:
            self.mozaik.get_key_share('a2aad3bb-8997-4384-84dd-d800b5587997')

        self.assertEqual(context.exception.code, 500)
        self.assertIn('ERROR:', context.exception.message)

    @patch('mozaik_obelisk.requests.post')
    def test_store_result_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_post.return_value = mock_response

        # No exception means success
        try:
            self.mozaik.store_result('a2aad3bb-8997-4384-84dd-d800b5587997', 'user_id', 'result')
        except ProcessException:
            self.fail("store_result() raised ProcessException unexpectedly!")

    @patch('mozaik_obelisk.requests.post')
    def test_store_result_failure(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        with self.assertRaises(ProcessException) as context:
            self.mozaik.store_result('a2aad3bb-8997-4384-84dd-d800b5587997', 'user_id', 'result')

        self.assertEqual(context.exception.code, 500)
        self.assertIn('ERROR:', context.exception.message)


if __name__ == '__main__':
    unittest.main()
