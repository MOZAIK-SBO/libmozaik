//
// Created by lschild on 20/02/24.
//

#include <iostream>
#include <fstream>
#include <filesystem>

#include "neural_net_evaluator.h"
#include "neural_net.h"

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cerr << "Please provide the path to the config directory and ciphertext file or directory" << std::endl;
        std::cerr << "Example: ./main_server [CONFIG_FILE] [CIPHERTEXT FILE]" << std::endl;
    }

    std::string config_dir = std::string(argv[1]);
    std::string ct_file = std::string(argv[2]);

}