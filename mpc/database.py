import sqlite3
import os

class Database:
    """
    Database class manages database operations.

    Attributes:
        db_path: The path to the database file.
    """
    def __init__(self, db_path):
        """
        Initialize Database with the provided parameters.

        Arguments:
            db_path (str) : The path to the database file.
        """
        self.db_path = db_path
        self.initialize_database()

    def initialize_database(self):
        """
        Initialize the database by creating the inference table if it doesn't exist, with 3 columns, analysis_id, status and result.
        """
        try:
            db_connection = sqlite3.connect(self.db_path)
            db_cursor = db_connection.cursor()
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS inference_results (
                    analysis_id TEXT PRIMARY KEY,
                    status TEXT,
                    result TEXT
                )
            ''')
            db_connection.commit()
            db_connection.close()
        except Exception as e:
            raise Exception(f"Error initializing database: {e}")
        finally:
            db_connection.close()

    def create_entry(self, analysis_id):
        """
        Create a new entry in the database or update an existing entry if it already exists.

        Arguments:
            analysis_id (str) : The analysis ID.

        Returns:
            A tuple containing the response message and HTTP status code.
        """
        try:
            # Check if the entry exists in the database
            db_connection = sqlite3.connect(self.db_path)
            db_cursor = db_connection.cursor()
            db_cursor.execute('SELECT * FROM inference_results WHERE analysis_id = ?', (analysis_id,))
            existing_entry = db_cursor.fetchone()

            if existing_entry is None:
                # If the entry doesn't exist, create it
                db_cursor.execute('''
                    INSERT INTO inference_results (analysis_id, status)
                    VALUES (?, ?)
                ''', (analysis_id, 'Queuing'))
                db_connection.commit()
                db_connection.close()
                return {"status": "Request added to the queue"}, 201
            else:
                # If the entry exists, update it
                db_cursor.execute('''
                    UPDATE inference_results
                    SET status = ?
                    WHERE analysis_id = ?
                ''', ('Queuing', analysis_id))
                db_connection.commit()
                db_connection.close()
                return {"status": "A request with this ID had already been created, the previous result will be overwritten"}, 202
        except Exception as e:
            raise Exception(f"Error creating entry: {e}")
        finally:
            db_connection.close()

    def set_status(self, analysis_id, status):
        """
        Set the status of an analysis in the database.

        Arguments:
            analysis_id (str) : The ID of the analysis.
            status (str) : The status to set.
        """
        try:
            # Insert the status message into the database
            db_connection = sqlite3.connect(self.db_path)
            db_cursor = db_connection.cursor()
            db_cursor.execute('''
                UPDATE inference_results
                SET status = ?
                WHERE analysis_id = ?
            ''', (status, analysis_id))
            db_connection.commit()
            db_connection.close()
        except Exception as e:
            raise Exception(f"Error rewriting entry: {e}")
        finally:
            db_connection.close()

    def append_result(self, analysis_id, result):
        """
        Append a result to an analysis entry in the database.

        Args:
            analysis_id (str) : The analysis ID.
            result (any) : The result to append.

        Raises:
            Exception: If an error occurs while rewriting the entry.
        """
        try:
            # Insert the status message into the database
            db_connection = sqlite3.connect(self.db_path)
            db_cursor = db_connection.cursor()

            db_cursor.execute('SELECT * FROM inference_results WHERE analysis_id = ?', (analysis_id,))
            existing_entry = db_cursor.fetchone()

            if existing_entry[2] is None:
                # If the entry doesn't exist, create it
                db_cursor.execute('''
                    UPDATE inference_results
                    SET result = ?
                    WHERE analysis_id = ?
                ''', (result, analysis_id))
                db_connection.commit()
                db_connection.close()
            else:
                # If the entry exists, update it
                db_cursor.execute('''
                    UPDATE inference_results
                    SET result = result || ?
                    WHERE analysis_id = ?
                ''', (result, analysis_id))
                db_connection.commit()
                db_connection.close()
        except Exception as e:
            raise Exception(f"Error rewriting entry: {e}")
        finally:
            db_connection.close()

    def read_entry(self, analysis_id):
        """
        Read an analysis entry from the database.

        Arguments:
            analysis_id (str) : The analysis ID.

        Returns:
            The database entry.
        """
        try:
            # Connect to the database
            db_connection = sqlite3.connect(self.db_path)
            db_cursor = db_connection.cursor()

            # Check if the entry exists in the database
            db_cursor.execute('SELECT * FROM inference_results WHERE analysis_id = ?', (analysis_id,))
            db_entry = db_cursor.fetchone()
            
            return db_entry
        
        except Exception as e:
            raise Exception(f"Error reading entry: {e}")
        finally:
            db_connection.close()

    def delete_entry(self, analysis_id):
        """
        Delete an analysis entry from the database.

        Arguments:
            analysis_id (str) : The ID of the analysis.

        Raises:
            Exception: If an error occurs while deleting the entry.
        """
        try:
            db_connection = sqlite3.connect(self.db_path)
            db_cursor = db_connection.cursor()
            db_cursor.execute('DELETE FROM inference_results WHERE analysis_id = ?', (analysis_id,))
            db_connection.commit()
        except Exception as e:
            raise Exception(f"Error deleting entry: {e}")
        finally:
            db_connection.close()

    def delete_database(self):
        """
        Delete the database file.

        Raises:
            FileNotFoundError: If the database file does not exist.
            Exception: If an error occurs while deleting the file.
        """
        # Delete the database file if it exists
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
