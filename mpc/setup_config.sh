#!/bin/bash
# Function to print green message
print_green() {
  echo -e "\e[32m$1\e[0m"
}

# Function to print red message and exit
print_red_and_exit() {
  echo -e "\e[31m$1\e[0m"
  exit 1
}

# Check if party_id parameter is provided
if [ -z "$1" ]; then
  print_red_and_exit "Usage: $0 <party_id>"
fi

# Change directory to mpc/rep3aes or exit with error message
cd rep3aes || print_red_and_exit "Failed to change directory"

# Run cargo build --verbose
print_green "Building rep3aes"
cargo build --release || print_red_and_exit "Cargo build failed"

# Change directory to MP-SPDZ
cd ../MP-SPDZ || print_red_and_exit "Failed to change directory"

# Write HOSTS file
print_green "Writing HOSTS file"
printf "10.10.168.46:8000\n10.10.168.47:8000\n10.10.168.48:8000\n10.10.168.49:8000\n" > HOSTS

# Write MP-SPDZ config file
print_green "Writing CONFIG.mine file"
printf "MY_CFLAGS += -I./local/include -DOUR_TRUNC -DBATCH_VFY" > CONFIG.mine

# Build malicious-rep-ring-party.x
print_green "Building malicious-rep-ring-party.x"
make malicious-rep-ring-party.x || print_red_and_exit "Failed to build malicious-rep-ring-party.x"

# Rewrite MP-SPDZ config file for insecure pre-processing
print_green "Rewriting CONFIG.mine file for insecure pre-processing"
printf "MY_CFLAGS += -I./local/include -DOUR_TRUNC -DBATCH_VFY -DINSECURE" > CONFIG.mine

# Build Fake-Offline.x
print_green "Building Fake-Offline.x"
make Fake-Offline.x || print_red_and_exit "Failed to build Fake-Offline.x"

# Compile using compile.py
print_green "Compiling heartbeat_inference_demo programs"
./compile.py -R64 heartbeat_inference_demo || print_red_and_exit "Compilation failed"
./compile.py -R64 heartbeat_inference_demo_batched_1 || print_red_and_exit "Compilation failed"
./compile.py -R64 heartbeat_inference_demo_batched_2 || print_red_and_exit "Compilation failed"
./compile.py -R64 heartbeat_inference_demo_batched_4 || print_red_and_exit "Compilation failed"
./compile.py -R64 heartbeat_inference_demo_batched_64 || print_red_and_exit "Compilation failed"
./compile.py -R64 heartbeat_inference_demo_batched_128 || print_red_and_exit "Compilation failed"

# Setup new TLS keys between the MPC parties
if [ "$1" -eq 0 ]; then
  print_green "Generating new TLS certificates"
  Scripts/setup-ssl.sh 3 || print_red_and_exit "Failed to generate TLS certificates"
  print_green "Distributing TLS certificates from P0 to P1 and P2"
  scp Player-Data/P* root@10.10.168.47:~/libmozaik/mpc/MP-SPDZ/Player-Data || print_red_and_exit "Failed to send certificates to P1"
  scp Player-Data/P* root@10.10.168.48:~/libmozaik/mpc/MP-SPDZ/Player-Data || print_red_and_exit "Failed to send certificates to P2"
fi

# Move deployment keys to rep3aes/keys directory
print_green "Moving deployment keys to rep3aes/keys directory"
mv ../rep3aes-deployment-keys/p* ../rep3aes/keys/ || print_red_and_exit "Failed to move deployment keys"

# Change directory to rep3aes
cd ../rep3aes || print_red_and_exit "Failed to change directory"

# Write TOML configuration file for all parties
party_index=$(( $1 + 1 ))
print_green "Writing TOML configuration file for party $1"
cat << EOF > "p${party_index}.toml"
party_index = $party_index

[p1]
address = "10.10.168.46"
port = 8100
certificate = "keys/p1.pem"
private_key = "keys/p1.key"

[p2]
address = "10.10.168.47"
port = 8101
certificate = "keys/p2.pem"
private_key = "keys/p2.key"

[p3]
address = "10.10.168.48"
port = 8102
certificate = "keys/p3.pem"
private_key = "keys/p3.key"
EOF

# Change directory back to mpc
cd ../

# Edit the run_server.sh script and insert the party_index parameter
print_green "Editing run_server.sh to insert the party_index parameter"
sed -i "s|^\(tmux new-session -d -s \"mozaik_app\" 'python3 main.py server\)[0-9]*\(.*\)$|\1${1}\2|g" run_server.sh || print_red_and_exit "Failed to edit run_server.sh"

# Run test_mpc_deployment script
print_green "Running test_mpc_deployment script for party $1"
python3 test_mpc_deployment.py "$1" || print_red_and_exit "Failed to run test_mpc_deployment.py"

print_green "Configuration completed successfully!"

print_green "Starting the server in a tmux session"
bash run_server.sh || print_red_and_exit "Failed to run run_server.sh"
