//
// Created by leonard on 2/20/25.
//

#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;
#include "neural_net_evaluator.h"

int main(int argc, char** argv) {

    if (argc < 4) {
        std::cerr << "Usage: ./ciphertext_combine [CRYPTO_CONFIG_PATH] [CT_OUT_NAME] [CT_0] [CT_1] [...CT]" << std::endl;
        std::cerr << "Example: ./ciphertext_combine ./default ct_combined ct0 ct1" << std::endl;
        std::exit(0);
    }

    const std::string suffix = "json";
    std::string config = std::string(argv[1]);
    auto ct_count = argc - 3;
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

    auto ct_acc = ckks_nn::NeuralNetEvaluator::load_ciphertext_from_file(argv[3]);
    auto nn_eval = ckks_nn::NeuralNetEvaluator(config_dir);

    auto& context = nn_eval.m_cc;

    auto stride = ct_count <= 4 ? 256 * 64 : 256;

    for (int32_t i = 0; i < ct_count; i++) {
        std::string ct_i_name = std::string(argv[i + 3]);
        auto base_ct = ckks_nn::NeuralNetEvaluator::load_ciphertext_from_file(ct_i_name);;
        uint32_t base_i = i;
        uint32_t current_shift = 0;
        while (base_i != 0) {
            auto bit = base_i & 1;
            if (bit) {
                base_ct = context->EvalRotate(base_ct, stride * int32_t(bit << current_shift));
            }
            base_i >>= 1;
            current_shift++;
        }

        context->EvalAddInPlace(ct_acc, base_ct);
    }

    std::string out_name = std::string(argv[2]);
    ckks_nn::NeuralNetEvaluator::write_results(ct_acc, out_name);
}