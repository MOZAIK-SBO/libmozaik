//
// Created by leonard on 2/20/25.
//

#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;
#include "neural_net_evaluator.h"

int main(int argc, char** argv) {

    if (argc < 3) {
        std::cerr << "Usage: ./ciphertext_split [CRYPTO_CONFIG_PATH] [CIPHERTEXT_FILE] [NUMBER OF SPLITS]" << std::endl;
        std::cerr << "Example: ./ciphertext_split default ct 30" << std::endl;
        std::exit(0);
    }

    const std::string suffix = "json";
    std::string config = std::string(argv[1]);
    auto ct_count = std::stol(argv[3]);
    std::string config_dir;

    // This is sketchy, sue me.
    // Does the file end with 'json' => if yes, is a config file
    if (config.rfind(suffix) == (config.size() - 4)) {
        auto path = fs::path(config);
        config_dir = path.parent_path().string();
    } else {
        // assume path is a directory
        if (!fs::is_directory(config)) {
            std::cerr << "Path provided must be a directory or json file. Exiting..." << std::endl;
            std::exit(-1);
        }
        // cursed
        config_dir = fs::path(config).string();
    }

    std::string ct_file = std::string(argv[2]);
    std::string out_file;

    auto ct = ckks_nn::NeuralNetEvaluator::load_ciphertext_from_file(ct_file);
    auto nn_eval = ckks_nn::NeuralNetEvaluator(config_dir);

    auto& context = nn_eval.m_cc;

    auto stride = ct_count <= 4 ? 256 * 64 : 256;
    for (int32_t i = 0; i < ct_count; i++) {

        auto base_ct = ct;
        uint32_t base_i = i;
        uint32_t current_shift = 0;
        while (base_i != 0) {
            auto bit = base_i & 1;
            if (bit) {
                base_ct = context->EvalRotate(base_ct, -stride * int32_t(bit << current_shift));
            }
            base_i >>= 1;
            current_shift++;
        }

        auto idx = std::to_string(i);
        auto res_name = ct_file + idx;
        ckks_nn::NeuralNetEvaluator::write_results(base_ct, res_name);
    }

}