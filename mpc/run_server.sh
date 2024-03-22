#!/bin/bash

# Function to check if a tmux session exists
session_exists() {
    tmux has-session -t "$1" 2>/dev/null
}

# Function to run the Flask app in a tmux session
run_flask_app() {
    # Redirect stdout and stderr to a log file
    python3 main.py server0.toml > mozaik_app.log 2>&1
}

# Main script
if session_exists "test"; then
    # If the session exists, kill it first
    tmux kill-session -t "mozaik_app"
fi

# Create a new tmux session named "test" and run the Flask app
tmux new-session -d -s "mozaik_app" 'run_flask_app'

echo "The webserver is running in the tmux session named 'mozaik_app'."
