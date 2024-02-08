import sqlite3
from flask import jsonify

class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self.initialize_database()

    def initialize_database(self):
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
                return jsonify(status="Request added to the queue"), 201
            else:
                # If the entry exists, update it
                db_cursor.execute('''
                    UPDATE inference_results
                    SET status = ?
                    WHERE analysis_id = ?
                ''', ('Queuing', analysis_id))
                db_connection.commit()
                db_connection.close()
                return jsonify(status="A request with this ID had already been created, the previous result will be overwritten"), 202
        except Exception as e:
            raise Exception(f"Error creating entry: {e}")
        finally:
            db_connection.close()

    def set_status(self, analysis_id, status):
        try:
            # Insert the status message into the database
            db_connection = sqlite3.connect(self.db_path)
            db_cursor = db_connection.cursor()
            db_cursor.execute('''
                INSERT INTO inference_results (analysis_id, status)
                VALUES (?, ?)
            ''', (analysis_id, status))
            db_connection.commit()
            db_connection.close()
        except Exception as e:
            raise Exception(f"Error rewriting entry: {e}")
        finally:
            db_connection.close()

    def append_result(self, analysis_id, result):
        try:
            # Insert the status message into the database
            db_connection = sqlite3.connect(self.db_path)
            db_cursor = db_connection.cursor()
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
        try:
            db_connection = sqlite3.connect(self.db_path)
            db_cursor = db_connection.cursor()
            db_cursor.execute('DELETE FROM inference_results WHERE analysis_id = ?', (analysis_id,))
            db_connection.commit()
        except Exception as e:
            raise Exception(f"Error deleting entry: {e}")
        finally:
            db_connection.close()
