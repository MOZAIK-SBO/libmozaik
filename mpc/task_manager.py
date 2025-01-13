import os
import subprocess
import struct
import queue
import threading
import time

from mozaik_obelisk import MozaikObelisk
from rep3aes import dist_dec, dist_enc
from key_share import MpcPartyKeys, decrypt_key_share
from config import DEBUG, ProcessException


class TaskManager:
    """
    TaskManager class manages tasks related to computations on the encrypted data received from Mozaik-Obelisk.

    Attributes:
        app (Flask): The Flask application instance.
        db (Database): The database instance.
        config (Config): The configuration object.
        aes_config (Rep3AesConfig): The AES configuration object.
        keys (MpcPartyKeys): Instance of MpcPartyKeys for managing pubic keys.
        request_queue (queue.Queue): Queue for storing tasks.
        request_thread (threading.Thread): Thread for processing requests.
        mozaik_obelisk (MozaikObelisk): Instance of MozaikObelisk for interactions with the Mozaik Obelisk.
        request_lock (threading.Lock): Lock for ensuring thread safety.
        sharesfile (str): File path for storing shares for MP-SPDZ.
    """
    def __init__(self, app, db, config, aes_config, timer):
        """
        Initialize the TaskManager with the provided parameters.

        Argumentss:
            app (Flask): The Flask application instance.
            db (Database): The database instance.
            config (Config): The configuration object.
            aes_config (Rep3AesConfig): The AES configuration object.
        """
        self.app = app
        self.db = db
        self.config = config
        self.aes_config = aes_config
        self.keys = MpcPartyKeys(self.config.keys_config())
        self.timer = timer

        self.request_queue = queue.Queue()

        self.request_thread = threading.Thread(target=self.process_requests)
        self.request_thread.daemon = True
        self.request_thread.start()   

        self.mozaik_obelisk = MozaikObelisk('https://mozaik.ilabt.imec.be/api', self.config.CONFIG_SERVER_ID, self.config.CONFIG_SERVER_SECRET)
        self.request_lock = threading.Lock()
        self.sharesfile = f'MP-SPDZ/Persistence/Transactions-P{self.config.CONFIG_PARTY_INDEX}.data'


    def write_shares(self, analysis_id, data, append=False):
        """
        Takes as input a vector of rss shares in ring mod 2^64, encodes and writes the values to a file for MP-SPDZ readability.

        Argumentss:
            analysis_id (str): The analysis ID.
            data (list): The shares to write.
            append (bool, optional): Whether to append to an existing file. Defaults to False.
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
        try:
            with open(self.sharesfile, mode) as file:
                # Write the header data at the beginning of the file
                if not append:
                    file.write(header_data)
                # Encode and write the input 64-bit integers in little endian format
                for rss_share in data:
                    for u64_share in rss_share:
                        signed_share = (u64_share - 2**64) if (u64_share > 2**63) else u64_share
                        packed_share = struct.pack('<q', signed_share)
                        file.write(packed_share)
                file.flush()
        except Exception as e:
            raise ProcessException(analysis_id, 500, f'Error writing into a file: {e}')

    def read_shares(self, analysis_id, number_of_shares=5):
        """
        Read {number of RSSshares} as shares from the MP-SPDZ persistence file, decode them according to ring mod 2^64 and return them as a list

        Argumentss:
            analysis_id (str): The analysis ID.
            number_of_values (int, optional): Number of RSS shares to read. Defaults to 5.

        Returns:
            list: List of u64 RSS shares in form (x_i, x_{i+1}).
        """
        # Move the result to the targetfile
        if os.path.exists(self.sharesfile):
            try:
                # Open the file in binary read mode
                with open(self.sharesfile, 'rb') as binary_file:
                    # Get the file size
                    file_size = os.path.getsize(self.sharesfile)

                    # Calculate the start position for reading the last 80 bytes
                    start_position = max(0, file_size - 8*number_of_shares*2)

                    # Move the file pointer to the start position
                    binary_file.seek(start_position)

                    # Read the last 80 bytes
                    last_n_bytes = binary_file.read()

                    # Convert the last 80 bytes to a list of integers in little-endian format
                    output_shares = []
                    for i in range(0, len(last_n_bytes), 16):  # Group every 16 bytes together
                        values = struct.unpack('<qq', last_n_bytes[i:i+16])  # Unpack 16 bytes into 2 `q` (8-byte signed integers)
                        u64_values = [v + (1 << 64) if v < 0 else v for v in values]
                        output_shares.append(list(u64_values[::-1]))  # Append the u64 values as a list of RSS shares in form (x_i, x_{i+1})to output_shares
                    return output_shares

            except Exception as e:
                raise ProcessException(analysis_id, 500, f"Unable to interpret the result: {e}")
                # self.error_in_task(analysis_id, 500, f"Unable to interpret the result: {e}")
        else:
            raise ProcessException(analysis_id, 500, f"The output file does not exist: the file '{self.sharesfile}' does not exist.")
            # self.error_in_task(analysis_id, 500, f"The output file does not exist: the file '{self.sharesfile}' does not exist.")  

    
    def run_inference(self, analysis_id, program='heartbeat_inference_demo', online_only=False):
        """
        Run the ML inference in MP-SPDZ.

        Arguments:
            analysis_id (str): The analysis ID.
            program (str, optional): The program to run. Defaults to 'heartbeat_inference_demo'.
            online_only (bool, optional): Whether to run the online phase only (make sure to run offline before)
        """
        try:
            if online_only:
                result = subprocess.run(['Scripts/../malicious-rep-ring-party.x', '-v', '-F', '-ip', 'HOSTS', '-p', str(self.config.CONFIG_PARTY_INDEX), program],
                                    capture_output=True, text=True, check=False, cwd='MP-SPDZ')
            else:
                result = subprocess.run(['Scripts/../malicious-rep-ring-party.x', '-v', '-ip', 'HOSTS', '-p', str(self.config.CONFIG_PARTY_INDEX), program],
                                    capture_output=True, text=True, check=False, cwd='MP-SPDZ')
            
            if DEBUG:
                print("Captured Output:", result.stdout)
                print("Captured Error Output:", result.stderr)
            
            result.check_returncode()
        except subprocess.CalledProcessError as e:
            raise ProcessException(analysis_id, 500, f"Error running program {e}")
            # self.error_in_task(analysis_id, 500, f"Error running program {e}")

    def run_offline(self, distributed=True, offline_dest=['10.10.168.47:~/libmozaik/mpc/MP-SPDZ/Player-Data/', '10.10.168.48:~/libmozaik/mpc/MP-SPDZ/Player-Data/']):
        """
        Run the offline phase for malicious-rep-ring-party.x. The offline phase is ruun by P0. 

        Arguments:
            distributed (bool, optional): Specify whether to run the offline phase on multiple servers(True) or locally(False)
            offline_dest (list, optional): List of strings. Specify the destinations to send the pre-processed data to.

        Returns: 
            Str: status of the subprocess call ("OK" or exception)
        """
        if self.config.CONFIG_PARTY_INDEX == 0:
            try:
                result = subprocess.run(
                    ['./Fake-Offline.x', '3', '-lgp', '64'],
                    capture_output=True, text=True, check=True, cwd='MP-SPDZ'
                )
                if DEBUG:
                    print("Standard Output:", result.stdout)
                    print("Standard Error:", result.stderr)

                if distributed:
                    for dest in offline_dest:
                        try:
                            result = subprocess.run(
                                f'scp -r MP-SPDZ/Player-Data/3-* {str(dest)}', shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                            )
                            if DEBUG:
                                print(f'Finished transfering data to: {dest}, Standard Output: {result.stdout.decode()}')
                        except subprocess.CalledProcessError as e:
                            raise e

            except subprocess.CalledProcessError as e:
                raise e
        return "OK"

    def read_model_from_file(self, file_path):
        """
        Reads data from a file where each line contains pairs of integers separated by commas.

        Args:
            file_path (str): The file path to read from.

        Returns:
            list: List of RSS shares.
        """
        data = []
        with open(file_path, 'r') as file:
            for line in file:
                pairs = line.strip().split()
                pairs = [tuple(map(int, pair.split(','))) for pair in pairs]
                data.append(pairs)
        return data

    def set_model(self, analysis_id, analysis_type, input):
        """
        Reads shares of weights and biases, concatanates them together with input vector and writes into MP-SPDZ shares file

        Arguments:
            analysis_id (str): The analysis ID.
            analysis_type (str): The analysis type.
            input (list): The input data as RSS shares in the form (x_i, x_{i+1}).
        """
        if analysis_type == "Heartbeat-Demo-1":
            try:
                model=[]
                weights = self.read_model_from_file(f'heartbeat-inference-model/model_shares{self.config.CONFIG_PARTY_INDEX+1}.txt')
                biases = self.read_model_from_file(f'heartbeat-inference-model/biases_shares{self.config.CONFIG_PARTY_INDEX+1}.txt')
                for weight_pair in weights[0]:
                    model.append(weight_pair)
                for biases_pair in biases[0]:
                    model.append(biases_pair)
                for input_pair in input:
                    model.append(input_pair[::-1])
                self.write_shares(analysis_id, model)
            except Exception as e:
                raise ProcessException(analysis_id, 500, f'An error occured while setting weights: {e}')
                # self.error_in_task(analysis_id, 400, f'An error occured while setting weights: {e}')
        else:
            raise ProcessException(analysis_id, 500, f'Invalid analysis_type {analysis_type}. Current supported analysis_type is "Heartbeat-Demo-1".')
            # self.error_in_task(analysis_id, 400, f'Invalid analysis_type {analysis_type}. Current supported analysis_type is "Heartbeat-Demo-1".')


    def error_in_task(self, analysis_id, code, message):
        """
        Handle errors in a task.

        Arguments:
            analysis_id (str or list): The analysis ID(s).
            code (int): The HTTP error code.
            message (str): The error message.
        """
        if isinstance(analysis_id, list):
            for aid in analysis_id:
                self.db.set_status(aid, f'ERROR:{code}:{message}')
        elif isinstance(analysis_id, str):
            self.db.set_status(analysis_id, f'ERROR:{code}:{message}')
        with self.app.app_context():
            self.app.logger.error(f"Task: {analysis_id} Code {code}\n{message}")


    def process_requests(self, test=False):
        """
        Process requests in the queue. Run the computation on encrypted data. This entails: get data from Mozaik-Obelisk, run sequentially on each sample distributed decryption, inference, distributed encryption. The result is sent for storage to Mozaik-Obelisk.
        
        Args:
            test (bool, optional): Whether to run in test mode. Defaults to False.
        """
        while True:
            try:
                analysis_ids, user_ids, analysis_type, data_indeces, online_only, streaming = self.request_queue.get()
                if analysis_type == "Heartbeat-Demo-1":
                    # Lock to ensure thread safety
                    with self.request_lock:
                        # Get the user data corresponding to the user at the requested indices
                        input_data = self.mozaik_obelisk.get_data(analysis_ids, user_ids, data_indeces)

                        # Get the shares of the key 
                        encrypted_key_shares = self.mozaik_obelisk.get_key_share(analysis_ids)

                        try:
                            assert len(user_ids) == len(input_data) == len(encrypted_key_shares)
                        except AssertionError as e:
                            raise ProcessException(analysis_ids, 500, f'The length of input_data: {len(input_data)} should match the length of key shares: {len(encrypted_key_shares)} which should match the number of user_ids received: {len(user_ids)}. {e}')

                        key_shares = []
                        for i, encrypted_key_share in enumerate(encrypted_key_shares):
                            try:
                                if streaming is not None:
                                    key_shares.append(decrypt_key_share(self.keys, user_ids[i], "AES-GCM-128", streaming[i], analysis_type, encrypted_key_share))
                                else:
                                    key_shares.append(decrypt_key_share(self.keys, user_ids[i], "AES-GCM-128", data_indeces[i], analysis_type, encrypted_key_share))
                            except Exception as e:
                                raise ProcessException(analysis_ids[i], 500, f'An error occurred while decrypting key_share: {e}')
                                # self.error_in_task(analysis_id, 500, f'An error occurred while decrypting key_share: {e}')

                        # Insert the status message into the database
                        for analysis_id in analysis_ids:
                            self.db.set_status(analysis_id, 'Starting computation')
                        
                        dist_dec_args = []
                        for i, user_samples in enumerate(input_data):
                            for sample in user_samples:
                                # Define a sample = array of 187 elements
                                # Check whther sample is in the right format, if not, convert it to bytes
                                if isinstance(sample, str):
                                    # If sample is a string, assume it's a hexadecimal representation and convert to bytes
                                    sample = bytes.fromhex(sample)
                                elif not isinstance(sample, bytes):
                                    # If key_share is not bytes or a string, raise an error
                                    raise ProcessException(analysis_ids[i], 500,f'Could not convert input data to the right format. Sample is expected to be bytes or hex string.')
                                dist_dec_args.append((user_ids[i], key_shares[i], sample))

                        if DEBUG:
                            print(f'The vector length of dist_dec_args: {len(dist_dec_args)} (for reference should be equal to the batch_size = the total number of received samples)')

                        batch_size = len(dist_dec_args) 

                        try:
                            assert batch_size == 1 or batch_size == 2 or batch_size == 4 or batch_size == 64 or batch_size == 128
                        except AssertionError as e:
                            raise ProcessException(analysis_ids, 500, f'The current supported batch_size are: 1,2,4,64 and 128. {e}')

                        # run dist_dec on the batch
                        try:
                            decrypted_shares = dist_dec(self.aes_config, dist_dec_args)
                        except Exception as e:
                            if test:
                                raise e
                            raise ProcessException(analysis_ids, 500,f'An error occurred while processing requests: {e}')
                        
                        if any(x is None for x in decrypted_shares):
                            # a decryption failed (due to tag mismatch)
                            raise ProcessException(analysis_ids, 500,f'Decryption of a sample failed.')

                        # flatten the batch
                        decrypted_shares = [el for decrypt_res in decrypted_shares for el in decrypt_res]

                        # Set the model and input accordingly
                        self.set_model(analysis_ids, analysis_type, decrypted_shares)

                        # Run the inference on the single sample
                        self.run_inference(analysis_ids, program='heartbeat_inference_demo_batched_'+str(batch_size), online_only=online_only)

                        # Read and decode boolean shares in field from the Persistence file
                        shares_to_encrypt = self.read_shares(analysis_ids, number_of_shares=5*batch_size)

                        # Unflatten the list of shares to match corresponding users and analyses
                        shares_to_encrypt_unflattened = []
                        for i, user_samples in enumerate(input_data):
                            shares_to_encrypt_unflattened.append(shares_to_encrypt[i*len(user_samples)*5:i*len(user_samples)*5+len(user_samples)*5])

                        # Run distributed encryption on the concataneted final result
                        encrypted_shares = dist_enc(self.aes_config, self.keys, [(user_ids[i], analysis_ids[i], analysis_type, key_shares[i], shares_to_encrypt_unflattened[i]) for i in range(len(user_ids))])

                        if isinstance(encrypted_shares, list) and all(isinstance(encrypted_share, bytes) for encrypted_share in encrypted_shares):
                            self.mozaik_obelisk.store_result(analysis_ids, user_ids, [encrypted_share.hex() for encrypted_share in encrypted_shares])  
                        else:
                            raise ProcessException(analysis_ids, 500,f'Result of dist_dec is in the wrong format (expected: bytes), encrypted shares: {encrypted_shares}')                         
                    
                        # Update status in the database
                        for analysis_id in analysis_ids:
                            self.db.set_status(analysis_id, 'Completed')
                            self.timer.end(analysis_id)

                        # Remove the request from the queue after processing
                        if test:
                            break
                        self.request_queue.task_done()

                        del shares_to_encrypt
                        del shares_to_encrypt_unflattened
                        del encrypted_shares
                        
                else:
                    raise ProcessException(analysis_ids, 500, f'Invalid analysis_type: {analysis_type}. Current supported analysis_type is "Heartbeat-Demo-1".')
                    # self.error_in_task(analysis_id, 400, f'Invalid analysis_type {analysis_type}. Current supported analysis_type is "Heartbeat-Demo-1".')
                
                # Bookeeping
                del analysis_ids
                del user_ids
                del analysis_type
                del data_indeces
                del input_data
                del encrypted_key_share
                del key_shares
                del dist_dec_args

            except ProcessException as e:
                if test:
                    raise e
                self.error_in_task(analysis_ids, e.code, f'An exception happened during the processing of the request: {str(e)}')
    
