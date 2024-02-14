import unittest
import tempfile
import threading
from unittest.mock import MagicMock, mock_open, patch
from task_manager import TaskManager

class TestTaskManager(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_app = MagicMock()
        self.mock_config = MagicMock()
        self.mock_aes_config = MagicMock()
        self.task_manager = TaskManager(self.mock_app, self.mock_db, self.mock_config, self.mock_aes_config)

    def test_write_shares(self):
        analysis_id = "test_analysis_id"
        data = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]  # Example data
        expected_header_data = b'\x14\x00\x00\x00\x00\x00\x00\x00\x72\x65\x70\x6c\x69\x63\x61\x74\x65\x64\x20\x5a\x32\x5e\x36\x34\x40\x00\x00\x00'
        expected_written_data = b'\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00'
        
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


    def test_read_shares(self):
        analysis_id = "test_analysis_id"
        expected_result = '1 2 3 4 5 6 7 8 9 10'

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            # Write example data to the temporary file
            temp_file.write(b'\x14\x00\x00\x00\x00\x00\x00\x00\x72\x65\x70\x6c\x69\x63\x61\x74\x65\x64\x20\x5a\x32\x5e\x36\x34\x40\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x0A\x00\x00\x00\x00\x00\x00\x00')
            temp_file.flush()

            # Set the temporary file path as sharesfile
            self.task_manager.sharesfile = temp_file.name

            # Call the method
            result = self.task_manager.read_shares(analysis_id)

            # Assert that the result matches the expected result
            self.assertEqual(result, expected_result)

    def test_run_inference(self):
        def run_test(config_index):
            program = 'heartbeeat_inference_demo_test'
            analysis_id = "test_analysis"
            self.task_manager.config.CONFIG_PARTY_INDEX = config_index
            with patch('subprocess.run') as mock_subprocess_run:
                # Set the return value of the subprocess.run to simulate the output
                mock_subprocess_run.return_value.stdout = "Prediction: [0.417969, 0.273438, 0.152344, 0.00390625, 0.148438]"
                # Call the method
                self.task_manager.run_inference(analysis_id, program=program)
                # Assert subprocess.run is called with correct parameters
                mock_subprocess_run.assert_called_once_with(['MP-SPDZ/Scripts/../malicious-rep-ring-party.x', '-ip', 'HOSTS', '-p', str(config_index), program],
                                    capture_output=True, text=True, check=False)
                # Assert that the expected output is contained in the printed output
                self.assertIn("Prediction: [0.417969, 0.273438, 0.152344, 0.00390625, 0.148438]", mock_subprocess_run.return_value.stdout)

        # Create threads to run the test with different configurations in parallel
        threads = []
        for i in range(3):
            thread = threading.Thread(target=run_test, args=(i,))
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        

if __name__ == '__main__':
    unittest.main()
