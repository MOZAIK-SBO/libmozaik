import unittest
import tempfile
import shutil
from pathlib import Path
from base64 import urlsafe_b64encode
from worker import FHEDataManager

class TestFHEDataManager(unittest.TestCase):
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = FHEDataManager(base_path=self.temp_dir)

    def test_directories_created_on_init(self):
        # Ensure necessary directories are created by the __init__ method
        self.assertTrue((Path(self.temp_dir) / 'cache' / 'keys').exists())
        self.assertTrue((Path(self.temp_dir) / 'cache' / 'models').exists())

    def test_are_user_keys_in_cache(self):
        # Initially, it should return False because no keys are cached
        self.assertFalse(self.manager.are_user_keys_in_cache("user123")[0])

        # Simulate putting keys in cache
        user_key_dir = Path(self.temp_dir) / 'cache' / 'keys' / 'user123'
        user_key_dir.mkdir(parents=True, exist_ok=True)
        for key in self.manager.expected_keys:
            (user_key_dir / key).touch()

        # Create a dummy config file
        (user_key_dir / 'crypto_config.json').touch()

        # Now, it should return True because the keys are cached
        self.assertTrue(self.manager.are_user_keys_in_cache("user123")[0])

    def test_put_keys_into_cache(self):
        auto_key = urlsafe_b64encode(b"auto_key_data").decode('utf-8')
        mult_key = urlsafe_b64encode(b"mult_key_data").decode('utf-8')
        add_key = urlsafe_b64encode(b"add_key_data").decode('utf-8')
        boot_key = urlsafe_b64encode(b"boot_key_data").decode('utf-8')

        self.manager.put_keys_into_cache("user123", auto_key, mult_key, add_key, boot_key)

        user_key_dir = Path(self.temp_dir) / 'cache' / 'keys' / 'user123'
        for key in self.manager.expected_keys:
            self.assertTrue((user_key_dir / key).exists())

    def tearDown(self):
        # Clean up temporary directory
        shutil.rmtree(self.temp_dir)

if __name__ == '__main__':
    unittest.main()
