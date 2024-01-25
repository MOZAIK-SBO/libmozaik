import os
import struct
import subprocess
from flask import Flask, render_template, jsonify, request, abort
import uuid  # Import the uuid module for UUID validation
from flask_sslify import SSLify
import threading
import queue
import ssl
import sys
import requests # Lib to send http requests


import tomli as tomllib

def get_config():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv} path/to/config.toml')
        sys.exit(-1)
    with open(sys.argv[1], 'rb') as fp:
        return tomllib.load(fp)

config = get_config()
CONFIG_RESULTS_DIR = config['results_dir']
CONFIG_PORT = config['port']
CONFIG_CA_CERT = config['ca_cert']
CONFIG_SERVER_CERT = config['server_cert']
CONFIG_SERVER_KEY = config['server_key']
CONFIG_PARTY_INDEX = config['party_index']

app = Flask(__name__)
sslify = SSLify(app)

# Create a 'results' directory if it doesn't exist
os.makedirs(CONFIG_RESULTS_DIR, exist_ok=True)

# Create a queue to manage client requests
request_queue = queue.Queue()
error_queue = queue.Queue()
# Lock to ensure thread safety when processing requests
request_lock = threading.Lock()

"""
Analyse
"""

@app.route('/analyse/', methods=['GET','POST'])
def analyse():
    if request.method == 'POST':
        # Get JSON data from the request
        data = request.get_json()

        # Extract data fields
        request_id = data.get('analysis_id')
        user_id = data.get('user_id')
        data_index = data.get('data_index', [])
        user_key = data.get('user_key')
        analysis_type = data.get('analysis_type')
        input_array = data.get('sample', [])

        # Validate request_id as a UUIDv4
        try:
            request_uuid = uuid.UUID(request_id, version=4)
        except TypeError:
            return jsonify(error="Invalid request_id. Please provide a valid UUIDv4."), 400
        
        # Create a file with the request ID as its name in the 'results' folder
        targetfile = os.path.join(CONFIG_RESULTS_DIR, f'{request_id}.txt')
        # Check if the file with the request ID exists in the 'results' folder
        if not os.path.isfile(targetfile):
            # If it doesn't exist, create an empty file
            open(targetfile, 'w').close()

            # Add the request to the queue
            request_queue.put((request_id, input_array))
            return jsonify(status="Request added to the queue"), 201
        else:
            # Add the request to the queue
            request_queue.put((request_id, input_array))
            return jsonify(status="A request with this ID had already been created, the previous result will be overwritten"), 202
        
        
    return render_template('index.html')

def error_in_task(request_id, code, message):
    targetfile = os.path.join(CONFIG_RESULTS_DIR, f'{request_id}.txt')
    with open(targetfile, 'w') as fp:
        fp.write(f'ERROR:{code}:{message}')
    with app.app_context():
        app.logger.error(f"Task: {request_id} Code {code}\n{message}")

"""
Processing function
"""

def process_requests():
    while True:
        try:
            request_id, input_array = request_queue.get()
            # Lock to ensure thread safety
            with request_lock:
                if len(input_array) == 187:
                    try:
                        # Define the path to the file where shares are read from and written to
                        sharesfile = f'Persistence/Transactions-P{CONFIG_PARTY_INDEX}.data'

                        # Define the data to be written at the beginning
                        header_data = bytearray([
                            0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x72, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
                            0x65, 0x64, 0x20, 0x5a, 0x32, 0x5e, 0x36, 0x34,
                            0x40, 0x00, 0x00, 0x00
                        ])

                        # Open the binary file in write mode
                        if os.path.exists(sharesfile):
                            with open(sharesfile, 'wb') as file:
                                # Write the header data at the beginning of the file
                                file.write(header_data)
                                # Encode and write the input 64-bit integers in little endian format
                                for rss_share in input_array:
                                    for share in rss_share:
                                        packed_share = struct.pack('<q', share)
                                        file.write(packed_share)
                        else:
                            error_in_task(request_id, 500, 'MP-SPDZ Input file not found')
                            # Remove the request from the queue after processing
                            request_queue.task_done()
                            continue

                        targetfile = os.path.join(CONFIG_RESULTS_DIR, f'{request_id}.txt')
                        with open(targetfile, 'w') as file:
                            file.write("Starting computation")

                        # Run the binary program and capture its output
                        try:
                            print("Starting computation")
                            result = subprocess.run(['./malicious-rep-ring-party.x', '-ip', 'HOSTS', '-p', str(CONFIG_PARTY_INDEX), 'heartbeat_inference_demo'],
                                                     capture_output=True, text=True, check=False)
                            print("Finished computation")
                            
                            print("Captured Output:", result.stdout)
                            print("Captured Error Output:", result.stderr)
                            
                            result.check_returncode()
                            
                            # Move the result to the targetfile
                            if os.path.exists(sharesfile):
                                try:
                                    # Open the file in binary read mode
                                    with open(sharesfile, 'rb') as binary_file:
                                        # Get the file size
                                        file_size = os.path.getsize(sharesfile)

                                        # Calculate the start position for reading the last 80 bytes
                                        start_position = max(0, file_size - 80)

                                        # Move the file pointer to the start position
                                        binary_file.seek(start_position)

                                        # Read the last 80 bytes
                                        last_80_bytes = binary_file.read()

                                        # Convert the last 80 bytes to a list of integers in little-endian format
                                        output_shares = []
                                        for i in range(0, len(last_80_bytes), 8):
                                            value = struct.unpack('<q', last_80_bytes[i:i+8])[0]
                                            output_shares.append(value)

                                        if os.path.isfile(targetfile):
                                            with open(targetfile, 'w') as file:
                                                file.write(' '.join(map(str, output_shares[0::2])) + '\n')
                                        else:
                                            # If the file does not exist
                                            with app.app_context():
                                                app.logger.error(f"Targetefile {targetfile} does not exist")

                                except Exception as e:
                                    error_in_task(request_id, 500, f"Unable to interpret the result: {e}")

                            else:
                                error_in_task(request_id, 500, f"The output file does not exist: the file '{shares_result_path}' does not exist.")   
                            
                            # output = result.stdout

                            # # Write the output of the binary program to the file
                            # with open(targetfile, 'w') as file:
                            #     file.write(output)

                        except subprocess.CalledProcessError as e:
                            error_in_task(request_id, 200, f"Error running program {e}")
                    except ValueError:
                        error_in_task(request_id, 200, "Invalid input. Please enter valid numbers.")
                else:
                    error_in_task(request_id, 200, "Invalid number of elements. Input exactly 187 tuples of 2 integers")
            
                # Remove the request from the queue after processing
                request_queue.task_done()
        except Exception as e:
            if request_id != None:
                error_in_task(request_id, 500, f'An error occurred while processing requests: {e}')
            else:
                raise e
            
"""
MOZAIK-Obelisk 
"""    

def getData(user_id, data_index):
    mozaik_obelisk_url = '127.0.0.1'
    endpoint = '/getData'

    # Construct the full URL with parameters
    url = f'{mozaik_obelisk_url}{endpoint}?user_id={user_id}&data_index={data_index}'

    try:
        # Make the GET request
        response = requests.get(url)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse and return the user_data from the JSON response
            return response.json().get('user_data')
        else:
            # Print an error message if the request was not successful
            print(f'Error: {response.status_code} - {response.text}')
            return None
    except requests.RequestException as e:
        # Print an error message if the request encountered an exception
        print(f'RequestException: {e}')
        return None
    
def getKeyShare(analysis_id):
    mozaik_obelisk_url = '127.0.0.1'
    endpoint = '/getKeyShare'

    # Construct the full URL with parameters
    url = f'{mozaik_obelisk_url}{endpoint}?user_id={analysis_id}'

    try:
        # Make the GET request
        response = requests.get(url)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse and return the user_data from the JSON response
            return response.json().get('key_share')
        else:
            # Print an error message if the request was not successful
            print(f'Error: {response.status_code} - {response.text}')
            return None
    except requests.RequestException as e:
        # Print an error message if the request encountered an exception
        print(f'RequestException: {e}')
        return None
    
def storeResult(analysis_id, user_id, result):
    base_url = '127.0.0.1'
    endpoint = '/storeResult'

    # Construct the full URL
    url = f'{base_url}{endpoint}'

    # Define the payload (data to be sent in the POST request)
    payload = {
        'analysis_id': analysis_id,
        'user_id': user_id,
        'result': result
    }

    try:
        # Make the POST request
        response = requests.post(url, json=payload)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse and return any relevant information from the JSON response
            return response.json()
        else:
            # Print an error message if the request was not successful
            print(f'Error: {response.status_code} - {response.text}')
            return None
    except requests.RequestException as e:
        # Print an error message if the request encountered an exception
        print(f'RequestException: {e}')
        return None

"""
Results
"""
    
@app.route('/status', methods=['GET'])
def get_analysis_status():
    # Get JSON data from the request
    data = request.get_json()

    # Extract analysis_id from data
    analysis_id = data.get('analysis_id')

    # Check if analysis_id is provided
    if not analysis_id:
        return jsonify(error="Missing analysis_id in JSON data."), 400
    
    # Validate request_id as a UUIDv4
    try:
        request_uuid = uuid.UUID(analysis_id, version=4)
    except TypeError:
        return jsonify(error="Invalid analysis_id. Please provide a valid UUIDv4."), 400

    # Construct the targetfile path based on analysis_id
    targetfile = os.path.join(CONFIG_RESULTS_DIR, f'{analysis_id}.txt')

    # Check if the file with the analysis_id exists in the 'results' folder
    if os.path.isfile(targetfile):
        # If it exists, read its content
        with open(targetfile, 'r') as file:
            content = file.read()

        # Check if the content is non-empty before displaying it
        if content.strip():
            if content.startswith('ERROR:'):
                split_content = content.split(':')
                code = split_content[1]
                message = ':'.join(split_content[2:])
                print(message)
                return jsonify(type='FAILED', details=message), 200
            
            elif content.startswith('Starting computation'):
                return jsonify(type="RUNNING"), 200
            else:
                # Delete the file after if the computation was completed
                os.remove(targetfile)
                return jsonify(type="COMPLETED", prediction=content), 200
        else:
            return jsonify(type="QUEUED"), 200
    else:
        # If the file does not exist, return a 404
        return jsonify(error="The analysis ID is unknown"), 404

# Start a background thread to process requests
request_thread = threading.Thread(target=process_requests)
request_thread.daemon = True
request_thread.start()

if __name__ == '__main__':
    # Mutual TLS authentication
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CONFIG_SERVER_CERT, CONFIG_SERVER_KEY)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(CONFIG_CA_CERT)
    app.run(debug=True, host='0.0.0.0', port=CONFIG_PORT, ssl_context=context)

