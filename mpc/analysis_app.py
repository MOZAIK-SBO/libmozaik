from flask import Flask, render_template, jsonify, request, abort
from flask_sslify import SSLify
import ssl
import uuid
from config import Config
from task_manager import TaskManager
from database import Database

class AnalysisApp:
    def __init__(self, config_path):
        self.config = Config(config_path)
        self.app = Flask(__name__)
        self.sslify = SSLify(self.app)
        self.initialize()

    def initialize(self):
        # Initialize a database
        db = Database('ecg_inference_database.db')

        # Initialize the task manager
        task_manager = TaskManager(self.app, db, self.config.CONFIG_PARTY_INDEX)

        # Set up routes for Flask app (you need to define your routes)
        @self.app.route('/analyse/', methods=['GET', 'POST'])
        def analyse():
            if request.method == 'POST':
                # Get JSON data from the request
                data = request.get_json()

                # Extract data fields
                analysis_id = data.get('analysis_id')
                user_id = data.get('user_id')
                data_index = data.get('data_index', [])
                analysis_type = data.get('analysis_type')

                # Validate analysis_id and user_id as a UUIDv4
                try:
                    request_uuid = uuid.UUID(analysis_id, version=4)
                    # user_uuid = uuid.UUID(user_id, version=4)
                except TypeError:
                    return jsonify(error="Invalid analysis_id/user_id. Please provide a valid UUIDv4."), 400

                task_manager.request_queue.put((analysis_id, user_id, analysis_type, data_index)) 
                return db.create_entry(analysis_id)
                      
                
            return render_template('index.html')

        @self.app.route('/status', methods=['GET'])
        def get_analysis_status():
            # Get JSON data from the request
            data = request.get_json()

            # Extract analysis_id from data
            analysis_id = data.get('analysis_id')

            # Check if analysis_id is provided
            if not analysis_id:
                return jsonify(error="Missing analysis_id in JSON data."), 400
            
            # Validate analysis_id as a UUIDv4
            try:
                request_uuid = uuid.UUID(analysis_id, version=4)
            except TypeError:
                return jsonify(error="Invalid analysis_id. Please provide a valid UUIDv4."), 400
            
            db_entry =  db.read_entry(analysis_id)
        
            if db_entry is None:
                # If the entry does not exist, return an error
                return jsonify(error="The analysis ID is unknown"), 400

            # Extract the result field from the database entry
            status = db_entry[1]  # Assuming status is the second column
            result = db_entry[2]

            if status.startswith('ERROR:'):
                # If it starts with 'ERROR:', return the error details
                split_content = status.split(':')
                code = split_content[1]
                message = ':'.join(split_content[2:])
                return jsonify(type='FAILED', details=message), code

            elif status.startswith('Starting computation'):
                # If it starts with 'Starting computation', return 'RUNNING'
                return jsonify(type="RUNNING"), 200
            
            elif status.startswith('Queuing'):
                # If it starts with 'Queuing', return 'QUEUING'
                return jsonify(type="QUEUING"), 200
            
            elif status.startswith('Completed'):
                # If it starts with 'Completed', return 'Completed'
                return jsonify(type="COMPLETED", details = "Sending data to Obelisk"), 200
            
            elif status.startswith('Sent'):
                # If it starts with 'Sent', return 'COMPLETED' and delete the entry
                db.delete_entry(analysis_id)
                return jsonify(type="COMPLETED", details = "Computation completed and result was successfully sent to Obelisk. The DB entry of this analysis is now deleted."), 200

            elif not status.strip():
                # If it's empty, return 'FAILED'
                return jsonify(type="FAILED", details = "Troubleshooting required. DB entry created with no status entry written."), 500

            else:
                return jsonify(type="FAILED", details = f'Troubleshooting required. Consult the database entry: {status} and result: {result}'), 500

   
    def start_background_thread(self):
        # Run the Flask app
        if __name__ == '__main__':
            # Mutual TLS authentication
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.config.CONFIG_SERVER_CERT, self.config.CONFIG_SERVER_KEY)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(self.config.CONFIG_CA_CERT)
            self.app.run(debug=True, host='0.0.0.0', port=self.config.CONFIG_PORT, ssl_context=context)
        