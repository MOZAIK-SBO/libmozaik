source ./install_openfhe || exit;
mkdir build;
cmake -B build
cmake --build build --parallel 8 || exit;

mkdir -p ./SERVER/server_cache/bin;
mkdir -p ./SERVER/server_cache/cache/keys;
mkdir -p ./SERVER/server_cache/cache/models;
mkdir -p ./SERVER/server_cache/cache/models/Heartbeat-Demo-1;

cp build/fhe_server ./SERVER/server_cache/bin;
cp assets/configs/* ./SERVER/server_cache/cache/models/Heartbeat-Demo-1/;