import os
import struct
import subprocess
from flask import Flask, render_template, jsonify, request, abort
import uuid  # Import the uuid module for UUID validation
from flask_sslify import SSLify

app = Flask(__name__)
sslify = SSLify(app)

# Set the path to your SSL/TLS certificate and private key
ssl_cert_path = 'tls_certs/server_cert.pem'
ssl_key_path = 'tls_certs/server_key.pem'

# Set the paths to your trusted CA certificates
trusted_ca_paths = ['tls_certs/ca_cert.pem']  

# Check if the certificate and private key files exist
if not os.path.exists(ssl_cert_path) or not os.path.exists(ssl_key_path):
    raise Exception("SSL certificate or key not found.")

# Configure Flask to use the SSL/TLS certificate and key
app.config['SSL_CERT_PATH'] = ssl_cert_path
app.config['SSL_KEY_PATH'] = ssl_key_path

# Load trusted CAs
trusted_cas = []
for ca_path in trusted_ca_paths:
    if not os.path.exists(ca_path):
        raise Exception(f"CA certificate '{ca_path}' not found.")
    trusted_cas.append(ca_path)

@app.before_request
def verify_client_certificate():
    # Verify that the client certificate is present and signed by at least one trusted CA
    client_cert = request.environ.get('SSL_CLIENT_CERT')
    # if not client_cert:
    #     return "Client certificate not present.", 403
    
    valid_certificate = True    # for test only

    # for trusted_ca_path in trusted_cas:
    #     if client_cert.verify(trusted_ca_path):
    #         valid_certificate = True
    #         break

    if not valid_certificate:
        return "Client certificate not signed by a trusted CA.", 403

# Create a 'results' directory if it doesn't exist
results_dir = 'results'
os.makedirs(results_dir, exist_ok=True)

@app.route('/analyse/', methods=['GET','POST'])
def analyse():
    if request.method == 'POST':
        # Get the request ID and input array from the form
        request_id = request.form.get('request_id')
        input_array = request.form.getlist('input_array')

        # Validate request_id as a UUIDv4
        try:
            request_uuid = uuid.UUID(request_id, version=4)
        except TypeError:
            return "Invalid request_id. Please provide a valid UUIDv4.", 400

        # Ensure there are exactly 5 elements in the input array
        if len(input_array) == 1:
            try:
                # Convert input values to integers
                # input_array = [int(x) for x in input_array]

                inputfile = 'Player-Data/Input-P0-0.txt'
                with open(inputfile, 'w') as f:
                    # Write input values separated by spaces
                    f.write(' '.join(map(str, input_array)))

                # Run the binary program and capture its output
                try:
                    result = subprocess.run(['./malicious-rep-ring-party.x', '-p', os.system("cat ../playerid"), '-ip', 'HOSTS', 'MITBIH_inference'],
                                            capture_output=True, text=True, check=True)
                    output = result.stdout

                    # Create a file with the request ID as its name in the 'results' folder
                    filename = os.path.join(results_dir, f'{request_id}.txt')

                    # Write the output of the binary program to the file
                    # with open(filename, 'w') as file:
                    #     file.write(output)

                    return "Successfully executed.", 201
                except subprocess.CalledProcessError as e:
                    # If an error occurs during the program execution, return the error message
                    return f"Error running program: {e.stderr}", 500
            except ValueError:
                return "Invalid input. Please enter valid integers.", 400
        else:
            return "Input exactly 1 element", 400
    return render_template('index.html')

@app.route('/results/<uuid:request_id>', methods=['GET'])
def view_result(request_id):
    targetfile = os.path.join(results_dir, f'{request_id}.txt')
    shares_result_path = "Persistence/Transactions-P0.data"

    if os.path.exists(shares_result_path):
        try:
            # Open the file in binary read mode
            with open(shares_result_path, 'rb') as binary_file:
                # Get the file size
                file_size = os.path.getsize(shares_result_path)

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
                        for i in range(len(output_shares)):
                            file.write(str(output_shares[0::2]) + '\n')
                else:
                    # If the file does not exist, return a 404 error
                    return "The request_ID is unknown", 404

                # Print or use the list of integers as needed
                # print("Last 80 bytes interpreted as little-endian integers:", int_values)

        except Exception as e:
            print(f"An error occurred: {str(e)}")

    else:
        print(f"The file '{shares_result_path}' does not exist.")
    # Check if the file with the request ID exists in the 'results' folder
    
    if os.path.isfile(targetfile):
        # If it exists, read its content
        with open(targetfile, 'r') as file:
            content = file.read()

        # Check if the content is non-empty before displaying it
        if content.strip():
            return jsonify(type="READY",prediction=content)
        else:
            return jsonify(type="STILL_RUNNING")
    else:
        # If the file does not exist, return a 404 error
        return "The request_ID is unknown", 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')




