import json
import sys
from typing import Dict, Tuple, List

from flask import request, Flask, jsonify
from threading import Thread, RLock
from concurrent.futures import ThreadPoolExecutor, Future

from potion import make_potion
from mozaik_obelisk import MozaikObelisk
from config import  OBELISKSetup

import subprocess
from worker import FHEDataManager
class FHEServer:

    def __init__(self, base_url, base_path, max_cache_size, max_workers):
        self.base_url = base_url
        self.max_workers = max_workers
        # self.fhe_keys = FHEConfigFields
        self.data_worker = FHEDataManager(base_path=base_path, max_cache_size=max_cache_size)
        self.mozaik_obelisk = MozaikObelisk(OBELISKSetup.OBELISK_BASE.value, OBELISKSetup.SERVER_ID.value, OBELISKSetup.SERVER_SECRET.value)
        self.current_thread = None

        self.thread_status = dict()
        self.thread_executor = ThreadPoolExecutor(max_workers=max_workers)
        self.thread_status_lock = RLock()

        a = make_potion()

        self.flask_server: Flask = a

    def setup(self):

        @self.flask_server.route("/analyse/", methods=['POST'])
        def create_analysis_job():
            try:
                # Get JSON data from the request
                data = request.get_json()

                # Extract data fields
                analysis_id = data.get('analysis_id')
                user_id = data.get('user_id')
                data_index = data.get('data_index', [])
                analysis_type = data.get('analysis_type')
            except (ValueError, AttributeError) as e:
                return jsonify(
                    error=f"Error getting data from json POST request. Expecting analysis_id, user_id, data_index as an array, user_key and analysis_type. {e}"), 400

            if not isinstance(data_index, list):
                data_index = [data_index]

            result_future = self.thread_executor.submit(self.perform_complete_analysis, analysis_id, analysis_type,
                                                        user_id, data_index)
            with self.thread_status_lock:
                self.thread_status[analysis_id] = result_future

            return jsonify({"status": "Request added to the queue"}), 201

        @self.flask_server.route('/status/<analysis_id>', methods=['GET'])
        def get_analysis_status(analysis_id):

            if analysis_id not in self.thread_status.keys():
                return jsonify(type="UNKNOWN",error="Invalid analysis id or job already finished"), 500

            with self.thread_status_lock:

                result_future: Future = self.thread_status[analysis_id]
                if result_future.running():
                    return jsonify(type="STARTED"), 200
                elif result_future.cancelled():
                    return jsonify(type="CANCELLED"), 500
                elif result_future.done():
                    return jsonify(type="COMPLETED", details="Sending data to Obelisk"), 200
                return jsonify(type="UNKNOWN"), 500

    def perform_complete_analysis(self, analysis_id: str, analysis_type: str, user_id: str, data_index: List):

        user_in_cache, config_path = self.data_worker.get_user_keys_from_cache(user_id)

        if not user_in_cache:

            keys = self.mozaik_obelisk.get_keys(analysis_id=analysis_id)
            self.data_worker.put_keys_into_cache(user_id, keys['automorphism_key'], keys['multiplication_key'], keys["crypto_context"])
            config_path = self.data_worker.generate_config(user_id, analysis_type=analysis_type)

        ct_paths = []
        data_index_to_request = []

        # Check which ciphertexts are already present on disk
        for i, datum_index in enumerate(data_index):
            ct_in_cache, ct_path = self.data_worker.get_user_ct_from_cache(user_id, str(datum_index))
            if not ct_in_cache:
                data_index_to_request.append((i, datum_index))
            else:
                ct_paths.append((i, ct_path))

        # request remaining ones
        data_to_request = [v[1] for v in data_index_to_request]
        print(data_to_request)
        ct_data = self.mozaik_obelisk.get_data(analysis_id, user_id, data_to_request)

        if not isinstance(ct_data, list):
            ct_data = [ct_data]

        for (i, datum_index), ct_datum in zip(data_index_to_request, ct_data):
            ct_path = self.data_worker.put_ct_into_dir(user_id,str(datum_index),ct_datum)
            ct_paths.append((i, ct_path))

        ct_paths = sorted(ct_paths, key=lambda x: x[0])

        for i, ct_path in ct_paths:

            if analysis_type == "Heartbeat-Demo-1":
                inference_binary_path = self.data_worker.bin / "fhe_server"
                res = subprocess.call([str(inference_binary_path.absolute()), config_path, ct_path])


                # res = subprocess.check_output(["/usr/bin/touch", ct_path + ".out"])
                if self.data_worker.output_encoding == "JSON":
                    ct_out_data = open(ct_path + ".out.json","r").read()
                else:
                    ct_out_data = self.data_worker.encode_from_raw(open(ct_path + ".out","rb").read())
            else:
                ct_out_data = ""

            self.mozaik_obelisk.store_result(analysis_id, user_id, ct_out_data)

        with self.thread_status_lock:
            del self.thread_status[analysis_id]

        return "good"

    def run(self, host, port, cert="", key=""):
        if cert != "" and key != "":
            self.flask_server.run(host=host,port=port,ssl_context=(cert, key))


if __name__ == "__main__":

    if len(sys.argv) < 4:
        print("Usage: python server.py [BASE_PATH] [URL] [PORT] [CRT_FILE] [KEY_FILE]. Exiting...")
        sys.exit(-1)

    base_path = sys.argv[1]
    url = sys.argv[2]
    port = int(sys.argv[3])

    server = FHEServer(base_url=url, base_path=base_path, max_workers=5, max_cache_size=100)
    server.run(url, port)


