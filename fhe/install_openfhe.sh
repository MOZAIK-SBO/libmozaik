#!/bin/sh

# CHANGE ME
export CC=/usr/bin/clang
export CXX=/usr/bin/clang++

# Create directories and pull openfhe
rm -rf ./libs/*;
[ ! -d "./assets/dependencies/openfhe" ] && mkdir -p "./assets/dependencies/openfhe";
[ ! -d "./openfhe" ] && git clone https://github.com/openfheorg/openfhe-development.git openfhe;
cd openfhe || exit;
# Build openfhe
[ ! -d "./build" ] && mkdir build;
cd build || exit;
cmake .. -DCMAKE_BUILD_TYPE=Release -DNATIVE_SIZE=64 -DWITH_NATIVEOPT=ON -DBUILD_STATIC=ON -DBUILD_SHARED=OFF -DWITH_OPENMP=OFF -DCMAKE_INSTALL_PREFIX="$PWD/../../assets/dependencies/openfhe"
make -j 8;
make install
cd ../../;
