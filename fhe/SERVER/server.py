from typing import Dict, Tuple

from celery import Celery, shared_task, chain
from celery.result import AsyncResult, states

from flask import  request, Flask, jsonify
from potion import make_potion

import worker
class FHEServer:

    def __init__(self, base_url, base_path, max_cache_size, max_workers):
        self.base_url = base_url
        self.max_workers = max_workers
        self.data_worker = worker.FHEDataManager(base_path=base_path, max_cache_size=max_cache_size)

        a,b = make_potion()

        self.flask_server: Flask = a
        self.celery: Celery = b

    def setup(self):

        @self.flask_server.route("/analyse/")
        def create_analysis_job():

            if request.method == 'POST':

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

                res = chain(
                    self.prepare_analysis.s(user_id, analysis_id,analysis_type,data_index),
                     self.perform_analysis.s(),
                     self.finalize_analysis.s(),
                    task_id=analysis_id
                )()

                return jsonify({"status": "Request added to the queue"}), 201

        @self.flask_server.route('/status/<analysis_id>', methods=['GET'])
        def get_analysis_status(analysis_id):

            task = AsyncResult(analysis_id)

            match task.status:
                case states.SUCCESS:
                    return jsonify(type="COMPLETED", details = "Sending data to Obelisk"), 200
                case states.PENDING:
                    return jsonify(type="QUEUING", details="The analysis was queued or the ID is not valid"), 200
                case states.STARTED:
                    return jsonify(type="STARTED"), 200
                case states.FAILURE:
                    return jsonify(type="FAILED", error=str(task)), 500

            return jsonify(type="FAILED", details="Unknown exit code"), 500

    @shared_task(ignore_results=False,bind=True)
    def perform_analysis(self, crypto_config_path:str, ct_path:str, output_path:str):
        pass

    @shared_task(ignore_results=False,bind=True)
    def prepare_analysis(self, user_id:str, analysis_id:str, analysis_type: str, data_index: str):
        pass

    @shared_task(ignore_results=False,bind=True)
    def finalize_analysis(self, user_id:str, analysis_id:str, analysis_type: str):
        pass

    def run(self, host, port):
        self.flask_server.run(host=host,port=port)