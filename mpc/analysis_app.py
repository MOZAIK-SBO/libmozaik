import ssl
import ulid

from flask import Flask, render_template, jsonify, request, abort
from flask_sslify import SSLify

from config import Config
from database import Database
from rep3aes import Rep3AesConfig
from task_manager import TaskManager

class AnalysisApp:
    """
    AnalysisApp class initializes and manages a Flask application for running analyses.

    Attributes:
        config (Config): The configuration object.
        aes_config (Rep3AesConfig): The Rep3AesConfig object.
        app (Flask): The Flask application instance.
        db (Database): The database instance.
    """
    def __init__(self, config_path):
        """
        Initialize the AnalysisApp with the provided configuration path.

        Arguments:
            config_path (str): The path to the configuration (Config) file.
        """
        self.config = Config(config_path)
        self.aes_config = Rep3AesConfig(f'rep3aes/p{self.config.CONFIG_PARTY_INDEX + 1}.toml', 'rep3aes/target/release/rep3-aes-mozaik')
        self.app = Flask(__name__)
        print('Application started')
        self.db = Database('ecg_inference_database.db')
        self.initialize()
 
    def initialize(self):
        """
        Initialize the Flask app and set up routes.
        """
        # Initialize the task manager
        task_manager = TaskManager(self.app, self.db, self.config, self.aes_config)

        # Set up routes for Flask app (you need to define your routes)
        @self.app.route('/analyse/', methods=['GET', 'POST'])
        def analyse():
            """
            Analyse route to handle analysis requests. Puts data into a TaskManager queue which automatically triggers processing.

            Returns:
                JSON: The response containing the analysis status.
            """
            if request.method == 'POST':
                
                try:
                    # Get JSON data from the request
                    data = request.get_json()
                
                    # Extract data fields
                    analysis_id = data.get('analysis_id')
                    user_id = data.get('user_id')
                    data_index = data.get('data_index', [])
                    user_key = data.get('user_key')
                    analysis_type = data.get('analysis_type')
                except (ValueError, AttributeError) as e:
                    return jsonify(error=f"Error getting data from json POST request. Expecting analysis_id, user_id, data_index as an array, user_key and analysis_type. {e}"), 400

                # Validate analysis_id as a UUIDv4
                try:
                    ulid.from_str(analysis_id)
                    # ulid.from_str(user_id)
                except ValueError as e:
                    return jsonify(error=f"Invalid analysis_id. Please provide a valid ULID. {e}"), 400

                task_manager.request_queue.put((analysis_id, user_id, analysis_type, data_index)) 
                response = self.db.create_entry(analysis_id)
                return jsonify(response[0]), response[1]
            
        @self.app.route('/offline/', methods=['GET'])
        def prepare_offline():
            """
            Run the offline phase of the analysis to pre-process randomness.

            Returns:
                JSON: Result of the .
            """
            try:
                result = task_manager.run_offline()
            except Exception as e:
                return jsonify(status = f'Failed with Exception: {e}'), 500
            
            if result != "OK":
                return jsonify(status = f'Failed with Exception: {result}'), 500
            else:
                return jsonify(status = "OK"), 200          

        @self.app.route('/health', methods=['GET'])
        def health_check():
            """
            Route to perform a health check on the application.

            Returns:
                JSON: The health status of the application.
            """
            return jsonify(status="OK"), 200

        @self.app.route('/status/<analysis_id>', methods=['GET'])
        def get_analysis_status(analysis_id):
            """
            Route to get analysis status.

            Arguments:
                analysis_id (str): The analysis ID extracted from the URL path.

            Returns:
                JSON: The analysis status.
            """
            # Validate analysis_id as a UUIDv4
            try:
                ulid.from_str(analysis_id)
            except ValueError as e:
                    return jsonify(error=f"Invalid analysis_id. Please provide a valid UUIDv4. {e}"), 400
            
            db_entry =  self.db.read_entry(analysis_id)
        
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
                # If it starts with 'Sent', return 'COMPLETED' 
                # self.db.delete_entry(analysis_id)
                return jsonify(type="RUNNING", details = f"Some computations completed and results were successfully sent to Obelisk. {status}"), 200

            elif not status.strip():
                # If it's empty, return 'FAILED'
                return jsonify(type="FAILED", details = "Troubleshooting required. DB entry created with no status entry written."), 500

            else:
                return jsonify(type="FAILED", details = f'Troubleshooting required. Consult the database entry: {status} and result: {result}'), 500


    def start_background_thread(self):
        # Mutual TLS authentication
        print('Application started')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.config.CONFIG_SERVER_CERT, self.config.CONFIG_SERVER_KEY)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.config.CONFIG_CA_CERT)
        self.app.run(debug=True, host='0.0.0.0', port=self.config.CONFIG_PORT, ssl_context=context)
        