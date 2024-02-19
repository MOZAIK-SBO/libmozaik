#!/bin/sh

# CHANGE ME
export CC=/usr/bin/clang-17
export CXX=/usr/bin/clang++-17

# Create directories and pull openfhe
rm -rf ./libs/*;
[ ! -d "./assets/dependencies/openfhe" ] && mkdir -p "./assets/dependencies/openfhe";
[ ! -d "./openfhe" ] && git clone https://github.com/openfheorg/openfhe-development.git openfhe;
cd openfhe || exit;
# Build openfhe
[ ! -d "./build" ] && mkdir build;
cd build || exit;
if [[  $1 -eq 32 ]]; then
  cmake .. -DCMAKE_BUILD_TYPE=Debug -DNATIVE_SIZE=32 -DWITH_NATIVEOPT=ON -DBUILD_STATIC=ON -DBUILD_SHARED=OFF -DWITH_OPENMP=OFF -DCMAKE_INSTALL_PREFIX="$PWD/../../assets/dependencies/openfhe"
else
  cmake .. -DCMAKE_BUILD_TYPE=Debug -DNATIVE_SIZE=64 -DWITH_NATIVEOPT=ON -DBUILD_STATIC=ON -DBUILD_SHARED=OFF -DWITH_OPENMP=OFF -DCMAKE_INSTALL_PREFIX="$PWD/../../assets/dependencies/openfhe"
fi
make -j 8;
make install
cd ../../;
