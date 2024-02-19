import queue
import threading
import struct
import os
import subprocess
from mozaik_obelisk import MozaikObelisk
from rep3aes import dist_dec, dist_enc

class TaskManager:
    def __init__(self, app, db, config, aes_config):
        self.app = app
        self.db = db
        self.config = config
        self.aes_config = aes_config
        #Hardcode the pks of the parties
        self.keys = ['tls_certs/server1.crt', 'tls_certs/server2.crt', 'tls_certs/server3.crt'] 

        self.request_queue = queue.Queue()

        self.request_thread = threading.Thread(target=self.process_requests)
        self.request_thread.daemon = True
        self.request_thread.start()   

        self.mozaik_obelisk = MozaikObelisk('http://127.0.0.1')
        self.request_lock = threading.Lock()
        self.sharesfile = f'MP-SPDZ/Persistence/Transactions-P{self.config.CONFIG_PARTY_INDEX}.data'
        self.batch_size = 128


    def write_shares(self, analysis_id, data, append=False):
        """
        Takes as input a vector of rss shares in ring mod 2^64, encodes and writes the values to a file for MP-SPDZ readability.
        """
        # Define the data to be written at the beginning
        header_data = bytearray([
            0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x6d, 0x61, 0x6c, 0x69, 0x63, 0x69, 0x6f, 0x75, 
            0x73, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63,
            0x61, 0x74, 0x65, 0x64, 0x20, 0x5a, 0x32, 0x5e, 
            0x36, 0x34, 0x40, 0x00, 0x00, 0x00
        ])

        # Open the binary file in write or append mode
        mode = 'ab' if append else 'wb'

        # Open the binary file in write mode
        if os.path.exists(self.sharesfile):
            with open(self.sharesfile, mode) as file:
                # Write the header data at the beginning of the file
                if not append:
                    file.write(header_data)
                # Encode and write the input 64-bit integers in little endian format
                for rss_share in data:
                    for share in rss_share:
                        packed_share = struct.pack('<q', share)
                        file.write(packed_share)
        else:
            self.error_in_task(analysis_id, 500, 'MP-SPDZ Input file not found')
            # Remove the request from the queue after processing
            # request_queue.task_done()

    def read_shares(self, analysis_id):
        """
        Read shares from the MP-SPDZ persistence file, decode them according to ring mod 2^64 and return them as a single string
        """
        # Move the result to the targetfile
        if os.path.exists(self.sharesfile):
            try:
                # Open the file in binary read mode
                with open(self.sharesfile, 'rb') as binary_file:
                    # Get the file size
                    file_size = os.path.getsize(self.sharesfile)

                    # Calculate the start position for reading the last 80 bytes
                    start_position = min(38, file_size)

                    # Move the file pointer to the start position
                    binary_file.seek(start_position)

                    # Read the last 80 bytes
                    content = binary_file.read()

                    # Convert the last 80 bytes to a list of integers in little-endian format
                    output_shares = []
                    for i in range(0, len(content), 16):  # Group every 16 bytes together
                        values = struct.unpack('<qq', content[i:i+16])  # Unpack 16 bytes into 2 `q` (8-byte signed integers)
                        output_shares.append(list(values))  # Append the values as a list to output_shares

                    return output_shares

                    # Insert the result into the database
                    # self.db.append_result(analysis_id, result_str)

            except Exception as e:
                self.error_in_task(analysis_id, 500, f"Unable to interpret the result: {e}")
        else:
            self.error_in_task(analysis_id, 500, f"The output file does not exist: the file '{self.sharesfile}' does not exist.")  

    
    def run_inference(self, analysis_id, program = 'heartbeat_inference_demo'):
        try:
            print("Starting computation")
            result = subprocess.run(['MP-SPDZ/Scripts/../malicious-rep-ring-party.x', '-ip', 'HOSTS', '-p', str(self.config.CONFIG_PARTY_INDEX), program],
                                    capture_output=True, text=True, check=False)
            print("Finished computation")
            
            print("Captured Output:", result.stdout)
            print("Captured Error Output:", result.stderr)
            
            result.check_returncode()
        except subprocess.CalledProcessError as e:
            self.error_in_task(analysis_id, 500, f"Error running program {e}")

    def read_model_from_file(self, file_path):
        """
        Reads data from a file where each line contains pairs of integers separated by commas.
        """
        data = []
        with open(file_path, 'r') as file:
            for line in file:
                pairs = line.strip().split()
                pairs = [tuple(map(int, pair.split(','))) for pair in pairs]
                data.append(pairs)
        return data

    def set_model(self, analysis_id, analysis_type):
        if analysis_type == "Heartbeat-Demo-1":
            model=[]
            weights = self.read_model_from_file(f'heartbeat-inference-model/model_shares{self.config.CONFIG_PARTY_INDEX}.txt')
            biases = self.read_model_from_file(f'heartbeat-inference-model/biases_shares{self.config.CONFIG_PARTY_INDEX}.txt')
            for weight_pair in weights[0]:
                model.append(weight_pair)
            for biases_pair in biases[0]:
                model.append(biases_pair)
            self.write_shares(analysis_id, model)
        else:
            self.error_in_task(analysis_id, 400, f'Invalid analysis_type {analysis_type}. Current supported analysis_type is "Heartbeat-Demo-1".')


    def error_in_task(self, analysis_id, code, message):
        self.db.set_status(analysis_id, f'ERROR:{code}:{message}')
        with self.app.app_context():
            self.app.logger.error(f"Task: {analysis_id} Code {code}\n{message}")


    def process_requests(self):
        while True:
            try:
                analysis_id, user_id, analysis_type, data_index = self.request_queue.get()
                if analysis_type == "Heartbeat-Demo-1":
                    # Lock to ensure thread safety
                    with self.request_lock:
                        # Set the model accordingly
                        self.set_model(analysis_id, analysis_type)

                        # Get the user data corresponding to the user at the requested indices
                        status, response = self.mozaik_obelisk.get_data(user_id, data_index)

                        # Check if the get_data and to Obelisk was succesful
                        if status == "OK":
                            input_bytes = response
                        elif status == "Error":
                            self.error_in_task(analysis_id, response.status_code, response.text)
                        elif status == "Exception":
                            self.error_in_task(analysis_id, 500,f'RequestException: {response}')  

                        # Get the shares of the key 
                        status, response = self.mozaik_obelisk.get_key_share(analysis_id)

                        # Check if the get_key_share to Obelisk was succesful
                        if status == "OK":
                            key_share = response
                        elif status == "Error":
                            self.error_in_task(analysis_id, response.status_code, response.text)
                        elif status == "Exception":
                            self.error_in_task(analysis_id, 500,f'RequestException: {response}')   

                        """
                        NEED TO CHECK LENGTH IN BYTES AND PASS ON BYTES. 187*8+12+16
                        """
                        length_of_ciphertext = 187*8+12+16
                        number_of_samples = len(input_bytes) % length_of_ciphertext

                        # Insert the status message into the database
                        self.db.set_status(analysis_id, 'Starting computation')

                        for i in range(number_of_samples):
                            try:
                                # Define a sample = array of 187 elements
                                sample = input_bytes[i*length_of_ciphertext:i*length_of_ciphertext+length_of_ciphertext]

                                # Run distributed decryption algorithm on the received encrypted sample
                                decrypted_shares = dist_dec(self.aes_config, user_id, key_share, sample) 

                                # Write the shares to the Persistence file of MP-SPDZ for further processing
                                self.write_shares(analysis_id, decrypted_shares, append=True)

                                # Run the inference on the single sample
                                self.run_inference(analysis_id)

                                # Read and decode boolean shares in field from the Persistence file
                                shares_to_encrypt = self.read_shares(analysis_id)

                                # Run distributed encryption on the final result
                                encrypted_shares = dist_enc(self.aes_config, self.keys, user_id, analysis_id, analysis_type, key_share, shares_to_encrypt)

                                # Append the encrypted result to the database
                                self.db.append_result(analysis_id, encrypted_shares)
                            
                            except Exception as e:
                                self.error_in_task(analysis_id, 500, f'An error occurred while processing requests: {e}')

                            # Update status in the database
                            self.db.set_status(analysis_id, 'Completed')

                            # send the result to Obelisk
                            result = self.db.read_entry(analysis_id)
                            status, response = self.mozaik_obelisk.store_result(analysis_id, user_id, result)

                            # Check if the store_result to Obelisk was succesful
                            if status == "OK":
                                self.db.set_status(analysis_id, "Sent")
                            elif status == "Error":
                                self.error_in_task(analysis_id, response.status_code, response.text)
                            elif status == "Exception":
                                self.error_in_task(analysis_id, 500,f'RequestException: {response}')                                   
                    
                        # Remove the request from the queue after processing
                        self.request_queue.task_done()
                else:
                    self.error_in_task(analysis_id, 400, f'Invalid analysis_type {analysis_type}. Current supported analysis_type is "Heartbeat-Demo-1".')
            except Exception as e:
                if analysis_id != None:
                    self.error_in_task(analysis_id, 500, f'An error occurred while processing requests: {e}')
                else:
                    raise e
    
