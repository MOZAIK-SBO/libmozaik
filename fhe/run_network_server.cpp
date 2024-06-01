//
// Created by lschild on 20/02/24.
//

#include <iostream>
#include <fstream>
#include <filesystem>

#include "neural_net_evaluator.h"
#include "neural_net.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

namespace fs = std::filesystem;
using namespace ckks_nn;

int main(int argc, char* argv[]) {

    if (argc < 3) {
        std::cerr << "Usage: ./main_server [FHE_KEY_DIR || CRYPTO_CONFIG_PATH ] [CIPHERTEXT_FILE] [RESULT_FILE]" << std::endl;
        std::cerr << "If [RESULT_FILE] is not specified, we set [RESULT_FILE] = [CIPHERTEXT_FILE].out" << std::endl;
        std::cerr << "Example: ./main_server assets/configs/default ct1 ct1_result" << std::endl;
        std::exit(0);
    }

    const std::string suffix = "json";
    std::string config = std::string(argv[1]);
    std::string config_dir;
    std::string config_file;

    // This is sketchy, sue me.
    // Does the file end with 'json' => if yes, is a config file
    if (config.rfind(suffix) == (config.size() - 4)) {
        auto path = fs::path(config);
        config_dir = path.parent_path().string();
        config_file = path.filename().string();
    } else {
        // assume path is a directory
        if (!fs::is_directory(config)) {
            std::cerr << "Path provided must be a directory or json file. Exiting..." << std::endl;
            std::exit(-1);
        }
        // cursed
        config_dir = fs::path(config).string();
        config_file = "crypto_config.json";
    }

    std::string ct_file = std::string(argv[2]);
    std::string out_file;

    if (argc >= 4) {
        out_file = argv[3];
    } else {
        out_file = ct_file + ".out";
    }

    // Load neural network
    auto nn = NeuralNetEvaluator::build_nn_from_crypto_config(config_dir, config_file);
    // Load ciphertexts
    auto ciphertext = NeuralNetEvaluator::load_ciphertext_from_file(ct_file);
    // Evaluate
    auto nn_evaluator = NeuralNetEvaluator(config_dir);
    auto result = nn_evaluator.eval_network(nn, ciphertext);
    // Write result
    NeuralNetEvaluator::write_results(result, out_file);
}