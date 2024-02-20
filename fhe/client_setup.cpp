//
// Created by lschild on 20/02/24.
//

#include <iostream>
#include <fstream>
#include <filesystem>
#include "json.hpp"

#include "openfhe.h"

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {

    auto cwd = fs::current_path();

    std::string key_dir;
    if (argc < 2) {
        std::cerr << "[!!!] No path to neural network config or key directory given. Exiting..." << std::endl;
        std::exit(-1);
    } else if (argc < 3) {
        std::cerr << "[!] No key directory chosen, creating directory fhe_keys" << std::endl;
        key_dir = "fhe_keys";
    } else {
        key_dir = std::string(argv[2]);
    }

    auto full_key_dir = cwd / key_dir;

    if (fs::exists(full_key_dir)) {
        std::cerr << "[!!!] Directory already exists, exiting..." << std::endl;
        std::exit(-1);
    }

}