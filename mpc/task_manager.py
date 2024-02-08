import queue
import threading
import struct
import os
import subprocess
from mozaik_obelisk import MozaikObelisk

class TaskManager:
    def __init__(self, app, db, party_index):
        self.app = app
        self.db = db
        self.party_index = party_index

        self.request_queue = queue.Queue()

        self.request_thread = threading.Thread(target=self.process_requests)
        self.request_thread.daemon = True
        self.request_thread.start()   

        self.mozaik_obelisk = MozaikObelisk('127.0.0.1')
        self.request_lock = threading.Lock()
        self.sharesfile = f'Persistence/Transactions-P{self.party_index}.data'
        self.batch_size = 128


    def write_shares(self, analysis_id, data, type):
        """
        Takes as input a vector of rss shares in 'type'=ring/field mod 2^64, encodes and writes the values to a file for MP-SPDZ readability.
        """
        if type == 'ring':
            # Define the data to be written at the beginning
            header_data = bytearray([
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x72, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
                0x65, 0x64, 0x20, 0x5a, 0x32, 0x5e, 0x36, 0x34,
                0x40, 0x00, 0x00, 0x00
            ])

            # Open the binary file in write mode
            if os.path.exists(self.sharesfile):
                with open(self.sharesfile, 'wb') as file:
                    # Write the header data at the beginning of the file
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
        
        elif type == 'field':
            self.error_in_task(analysis_id, 501, 'todo')
        else:
            self.error_in_task(analysis_id, 500, 'Error writing shares into MP-SPDZ Persistence file. Supported structures are ring mod 2^64 and a field mod 2^64')

    def read_shares(self, analysis_id, type):
        """
        Read shares from the MP-SPDZ persistence file, decode them according to 'type'=ring/field mod 2^64 and return them as a single string
        """
        if type == 'ring':
            # Move the result to the targetfile
            if os.path.exists(self.sharesfile):
                try:
                    # Open the file in binary read mode
                    with open(self.sharesfile, 'rb') as binary_file:
                        # Get the file size
                        file_size = os.path.getsize(self.sharesfile)

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

                        # Convert the output shares to a string for storage in the database
                        result_str = ' '.join(map(str, output_shares[0::2]))

                        return result_str

                        # Insert the result into the database
                        # self.db.append_result(analysis_id, result_str)

                except Exception as e:
                    self.error_in_task(analysis_id, 500, f"Unable to interpret the result: {e}")

            else:
                self.error_in_task(analysis_id, 500, f"The output file does not exist: the file '{self.sharesfile}' does not exist.")  
        
        elif type == 'field':
            self.error_in_task(analysis_id, 501, 'todo')
        else:
            self.error_in_task(analysis_id, 500, 'Error reading shares from MP-SPDZ Persistence file. Supported structures are ring mod 2^64 and a field mod 2^64')


    def run_distributed_decryption(self, analysis_id, input_array):
        return None

    def run_distributed_encryption(self, analysis_id, input_array):
        return None
    
    def run_conversion_B2A(self, analysis_id):
        return None
    
    def run_conversion_A2B(self, analysis_id):
        return None
    
    def run_inference(self, analysis_id):
        try:
            print("Starting computation")
            result = subprocess.run(['./malicious-rep-ring-party.x', '-ip', 'HOSTS', '-p', str(self.party_index), 'heartbeat_inference_demo'],
                                    capture_output=True, text=True, check=False)
            print("Finished computation")
            
            print("Captured Output:", result.stdout)
            print("Captured Error Output:", result.stderr)
            
            result.check_returncode()
        except subprocess.CalledProcessError as e:
            self.error_in_task(analysis_id, 500, f"Error running program {e}")


    def error_in_task(self, analysis_id, code, message):
        self.db.set_status(analysis_id, f'ERROR:{code}:{message}')
        with self.app.app_context():
            self.app.logger.error(f"Task: {analysis_id} Code {code}\n{message}")


    def process_requests(self):
        while True:
            try:
                analysis_id, user_id, analysis_type, data_index = self.request_queue.get()
                if analysis_type == "ecg_inference":
                    # Lock to ensure thread safety
                    with self.request_lock:
                        # Get the user data corresponding to the user at the requested indices
                        status, response = self.mozaik_obelisk.get_data(user_id, data_index)

                        # Check if the get_data and to Obelisk was succesful
                        if status == "OK":
                            input_bytes = response
                        elif status == "Error":
                            self.error_in_task(analysis_id, response.status_code, response.text)
                        elif status == "Exception":
                            self.error_in_task(analysis_id, 500,f'RequestException: {e}')  

                        # Get the shares of the key 
                        status, response = self.mozaik_obelisk.get_key_share(analysis_id)

                        # Check if the get_key_share to Obelisk was succesful
                        if status == "OK":
                            key_share = response
                        elif status == "Error":
                            self.error_in_task(analysis_id, response.status_code, response.text)
                        elif status == "Exception":
                            self.error_in_task(analysis_id, 500,f'RequestException: {e}')   

                        input_array = [int.from_bytes(input_bytes[i:i+8], byteorder='little') for i in range(0, len(input_bytes), 8)]

                        number_of_samples = len(input_array) % 187

                        # Insert the status message into the database
                        self.db.set_status(analysis_id, 'Starting computation')

                        for i in range(number_of_samples):
                            try:
                                # Define a sample = array of 187 elements
                                sample = input_array[i*187:i*187+187]

                                # Run distributed decryption algorithm on the received encrypted sample
                                decrypted_shares = self.run_distributed_decryption(analysis_id, sample)  

                                # Write the shares to the Persistence file of MP-SPDZ for further processing
                                self.write_shares(analysis_id, decrypted_shares, 'field')

                                # Convert boolean shares in a field to arithmetic in a ring mod 2^64
                                self.run_conversion_B2A(analysis_id)

                                # Run the inference on the single sample
                                self.run_inference(analysis_id)

                                # Convert the output from inference to shares in a field
                                self.run_conversion_A2B(analysis_id)

                                # Read and decode boolean shares in field from the Persistence file
                                shares_to_encrypt = self.read_shares(analysis_id, 'field')

                                # Run distributed encryption on the final result
                                encrypted_shares = self.run_distributed_encryption(analysis_id, shares_to_encrypt)

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
                                self.error_in_task(analysis_id, 500,f'RequestException: {e}')                                   
                    
                        # Remove the request from the queue after processing
                        self.request_queue.task_done()
                else:
                    self.error_in_task(analysis_id, 400, f'Invalid analysis_type {analysis_type}. Current supported analysis_type is "ecg_inference".')
            except Exception as e:
                if analysis_id != None:
                    self.error_in_task(analysis_id, 500, f'An error occurred while processing requests: {e}')
                else:
                    raise e
    
