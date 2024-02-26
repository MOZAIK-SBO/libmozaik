import unittest
import os

from database import Database  

class DatabaseTests(unittest.TestCase):
    def setUp(self):
        # Create an in-memory SQLite database for testing
        self.db_path = 'test.db'
        self.db = Database(self.db_path)

    def test_create_entry(self):
        self.db.create_entry('1')
        entry = self.db.read_entry('1')
        self.assertIsNotNone(entry)
        self.assertEqual(entry[0], '1')
        self.assertEqual(entry[1], 'Queuing')

    def test_update_existing_entry(self):
        self.db.create_entry('2')
        self.db.create_entry('2')
        entry = self.db.read_entry('2')
        self.assertIsNotNone(entry)
        self.assertEqual(entry[0], '2')
        self.assertEqual(entry[1], 'Queuing')

    def test_set_status(self):
        self.db.create_entry('3')
        self.db.set_status('3', 'Processing')
        entry = self.db.read_entry('3')
        self.assertEqual(entry[1], 'Processing')

    def test_append_result(self):
        self.db.create_entry('4')
        self.db.append_result('4', 'result_part_1')
        self.db.append_result('4', 'result_part_2')
        entry = self.db.read_entry('4')
        self.assertEqual(entry[2], 'result_part_1result_part_2')

    def test_read_entry(self):
        self.db.create_entry('5')
        entry = self.db.read_entry('5')
        self.assertIsNone(entry[2])

    def test_delete_entry(self):
        self.db.create_entry('6')
        self.db.delete_entry('6')
        entry = self.db.read_entry('6')
        self.assertIsNone(entry)

    def tearDown(self):
        # Delete the database file if it exists
        if os.path.exists(self.db_path):
            os.remove(self.db_path)


if __name__ == '__main__':
    unittest.main()
