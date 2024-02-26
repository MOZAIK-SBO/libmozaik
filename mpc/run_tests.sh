#!/bin/bash

set -e

# Change directory to the mpc folder
cd mpc

# Run each test script one by one
python3 test.py
python3 test_analysis_app.py
python3 test_database.py
python3 test_mozaik_obelisk.py
python3 test_task_manager.py
