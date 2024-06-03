source ./install_openfhe || exit;
mkdir build;
cmake -B build
cmake --build build --target all || exit;
mkdir ./SERVER/server_cache
