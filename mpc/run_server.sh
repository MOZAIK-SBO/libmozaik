#!/bin/bash

# Function to check if a tmux session exists
session_exists() {
    tmux has-session -t "$1" 2>/dev/null
}

# Main script
if session_exists "mozaik_app"; then
    # If the session exists, kill it first
    tmux kill-session -t "mozaik_app"
fi

# Create a new tmux session named "test" and run the Flask app
tmux new-session -d -s "mozaik_app" 'python3 main.py server0.toml > mozaik_app.log 2>&1'

echo "The webserver is running in the tmux session named 'mozaik_app'."
