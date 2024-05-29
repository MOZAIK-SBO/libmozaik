from typing import Dict, Tuple

from celery import Celery, shared_task, chain
from celery.result import AsyncResult, states

from flask import request, Flask, jsonify
from potion import make_potion
from mozaik_obelisk import MozaikObelisk
from config import ServerConfig, OBELISKSetup, FHEConfigFields

import worker
class FHEServer:

    def __init__(self, base_url, base_path, max_cache_size, max_workers):
        self.base_url = base_url
        self.max_workers = max_workers
        self.fhe_keys = FHEConfigFields
        self.data_worker = worker.FHEDataManager(base_path=base_path, max_cache_size=max_cache_size)
        self.mozaik_obelisk = MozaikObelisk(OBELISKSetup.OBELISK_BASE, OBELISKSetup.SERVER_ID, OBELISKSetup.SERVER_SECRET)

        a,b = make_potion()

        self.flask_server: Flask = a
        self.celery: Celery = b

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

            self.res = chain(
                self.prepare_analysis.s(user_id, analysis_id,data_index),
                self.perform_analysis.s(analysis_type),
                self.finalize_analysis.s(user_id, analysis_id),
                task_id=analysis_id
            )()
            print(self.celery.tasks) 

            return jsonify({"status": "Request added to the queue"}), 201

        @self.flask_server.route('/status/<analysis_id>', methods=['GET'])
        def get_analysis_status(analysis_id):

            task = AsyncResult(analysis_id)

            if task.state == states.PENDING:
                return jsonify(type="QUEUING", details="The analysis was queued"), 200
            elif task.state == states.SUCCESS:
                return jsonify(type="COMPLETED", details="Sending data to Obelisk"), 200
            elif task.state == states.STARTED:
                return jsonify(type="STARTED"), 200
            elif task.state == states.FAILURE:
                return jsonify(type="FAILED", error=str(task)), 500
            else:
                return jsonify(type="FAILED", details="The querried ID is unknown"), 500


    @classmethod
    @shared_task(ignore_results=False,bind=True)
    def prepare_analysis(self, user_id:str, analysis_id:str, data_index:list):
        keys = MozaikObelisk.get_keys(analysis_id)
        worker.FHEDataManager.put_keys_into_cache(user_id, keys['automorphism_key'], keys['multiplication_key'], keys['addition_key'], keys['bootstrap_key'])
        return MozaikObelisk.get_data(analysis_id, user_id, data_index)


    @classmethod
    @shared_task(ignore_results=False,bind=True)
    def perform_analysis(self, analysis_type:str, ct_data:str):
        aut_key = self.fhe_keys.AUTOMORPHISM_KEY
        # Check the ct_data for correct format
        # if analysis_type == "Heartbeat-Demo-1"
        # Run inference
        # return output ct
        return 'output'

    @classmethod
    @shared_task(ignore_results=False,bind=True)
    def finalize_analysis(self, user_id:str, analysis_id:str, result_ct: str):
        MozaikObelisk.store_result(analysis_id, user_id, result_ct)
        return "good"

    def run(self, host, port):
        self.flask_server.run(host=host,port=port)