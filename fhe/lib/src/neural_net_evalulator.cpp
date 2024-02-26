//
// Created by lschild on 20/02/24.
//

#include "neural_net_evaluator.h"
#include "neural_net.h"
#include "json.hpp"
#include "typedefs.h"

#include "cryptocontext-ser.h"
#include "key/key-ser.h"

#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace ckks_nn {

    // Begin cursed
    // Basically, computing softmax homomorphically is difficult if we want to actually have a distribution output
    // so we do a second order taylor expansion around 0 and hope it's good enough
    static double grad_softmax_at_0[5][5] = {
            { 0.16, -0.04, -0.04, -0.04, -0.04},
            {-0.04,  0.16, -0.04, -0.04, -0.04},
            {-0.04, -0.04,  0.16, -0.04, -0.04},
            {-0.04, -0.04, -0.04,  0.16, -0.04},
            {-0.04, -0.04, -0.04, -0.04,  0.16}
    };

    static double hessian_softmax_at_0[5][5][5] = {{{0.096, -0.024, -0.024, -0.024, -0.024}, {-0.024, -0.024, 0.016, 0.016, 0.016}, {-0.024, 0.016, -0.024, 0.016, 0.016}, {-0.024, 0.016, 0.016, -0.024, 0.016}, {-0.024, 0.016, 0.016, 0.016, -0.024}}, {{-0.024, -0.024, 0.016, 0.016, 0.016}, {-0.024, 0.096, -0.024, -0.024, -0.024}, {0.016, -0.024, -0.024, 0.016, 0.016}, {0.016, -0.024, 0.016, -0.024, 0.016}, {0.016, -0.024, 0.016, 0.016, -0.024}}, {{-0.024, 0.016, -0.024, 0.016, 0.016}, {0.016, -0.024, -0.024, 0.016, 0.016}, {-0.024, -0.024, 0.096, -0.024, -0.024}, {0.016, 0.016, -0.024, -0.024, 0.016}, {0.016, 0.016, -0.024, 0.016, -0.024}}, {{-0.024, 0.016, 0.016, -0.024, 0.016}, {0.016, -0.024, 0.016, -0.024, 0.016}, {0.016, 0.016, -0.024, -0.024, 0.016}, {-0.024, -0.024, -0.024, 0.096, -0.024}, {0.016, 0.016, 0.016, -0.024, -0.024}}, {{-0.024, 0.016, 0.016, 0.016, -0.024}, {0.016, -0.024, 0.016, 0.016, -0.024}, {0.016, 0.016, -0.024, 0.016, -0.024}, {0.016, 0.016, 0.016, -0.024, -0.024}, {-0.024, -0.024, -0.024, -0.024, 0.096}}};

    std::vector<std::vector<double>> setup_matrix_for_mult(double mat[5][5]) {
        std::vector<std::vector<double>> ret(5);

        for(int i = 0; i < 5; i++)
            ret[i].resize(5);

        for(int i = 0; i < 5; i++) {
            for(int j = 0; j < 5; j++) {
                auto new_i = (i + j) % 5;
                ret[i][j] = mat[new_i][j];
            }
        }
    }

    // End cursed
    CKKSCiphertext NeuralNetEvaluator::eval_network(const ckks_nn::NeuralNet &nn, CKKSCiphertext &input) {
        auto layer_i_out = eval_layer(nn, 0, input);
        for(int_type i=1; i < nn.get_n_layers(); i++) {
            layer_i_out = eval_layer(nn, i, layer_i_out);
        }

        return layer_i_out;
    }

    CKKSCiphertext NeuralNetEvaluator::eval_layer(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                  ckks_nn::CKKSCiphertext &vector) {

        CKKSCiphertext tmp = eval_mat_mul(nn, layer_idx, vector);

        // add bias
        auto bias_vec = nn.get_bias_vector(layer_idx);
        auto bias_encoded = m_cc->MakeCKKSPackedPlaintext(bias_vec);
        m_cc->EvalAddInPlace(tmp, bias_encoded);
        return eval_activation(nn, layer_idx, tmp);

    }

    CKKSCiphertext NeuralNetEvaluator::eval_mat_mul(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                          ckks_nn::CKKSCiphertext &vector) {
        auto dim = nn.get_weight_dim(layer_idx);
        auto rows = dim.first;

        std::vector<double> row(m_batch_size);
        std::vector<CKKSCiphertext> temp_results;
        for(int_type i = 0; i < rows; i++) {
            auto row_i = nn.get_weight_col(layer_idx, i);
            row_i.resize(m_batch_size);
            auto row_ptx = m_cc->MakeCKKSPackedPlaintext(row_i);

            auto inner_prod = m_cc->EvalInnerProduct(vector, row_ptx, m_batch_size);
            temp_results.push_back(inner_prod);
        }

        return m_cc->EvalMerge(temp_results);
    }

    CKKSCiphertext
    NeuralNetEvaluator::eval_activation(const ckks_nn::NeuralNet &nn, int_type layer_idx,
                                        ckks_nn::CKKSCiphertext &vector) {
        auto activation = nn.get_activation(layer_idx);
        auto bounds = nn.get_bounds(layer_idx);
        auto dims = nn.get_weight_dim(layer_idx);

        switch (activation) {
            case NeuralNet::Activation::RELU: {
                auto func = [](double x) -> double { return x > 0 ? x : -x;};
                //return m_cc->EvalChebyshevFunction(func, vector, static_cast<double>(bounds.first), static_cast<double>(bounds.second), 2000);
                auto tmp = m_cc->EvalChebyshevFunction(func, vector, -3, 3, 2000);
                m_cc->EvalAddInPlace(tmp, vector);
                std::vector<double> d2(m_batch_size);
                std::fill(d2.begin(),d2.end(), 1.0/2);
                auto pt = m_cc->MakeCKKSPackedPlaintext(d2);

                return m_cc->EvalMult(tmp, pt);
            }
            case NeuralNet::Activation::SOFTMAX: {


                // TODO: implement linearization of softmax around [0,0...,0]



                std::vector<double> exp_taylor = {1, 1, 0.5};
                // unclean solution for now
                // m_cc->EvalSubInPlace(vector, (double) bounds.second);
                double new_lowerbound = bounds.first - bounds.second + 1;
                auto func = [](double x) -> double { return std::exp(x); };

                // v_i' = exp(v_i)
                auto enc_exp = m_cc->EvalPoly(vector, exp_taylor);

                // w_j = \sum v_i' = \sum exp(v_i)
                auto extracted = m_cc->EvalSum(enc_exp, dims.second);
                // x_i = 1 / w_i
                auto extract_inv = m_cc->EvalDivide(extracted, 1, 10, 256);
                // out_i = v_i' / w_i = exp(v_i) / \sum exp(v_i)
                return extract_inv; // m_cc->EvalMult(extract_inv, enc_exp);
            }
            default: break;
        }
        return vector;
    }

    NeuralNet NeuralNetEvaluator::build_nn_from_crypto_config(const std::string& config_dir_path, const std::string& config_name) {
        auto config_path = config_dir_path + config_name;

        std::ifstream config_stream(config_path);
        json config = json::parse(config_stream);

        // TODO error handling
        std::string nn_path = config[NN_STRING];

        return NeuralNet(config_dir_path, nn_path);
    }

    NeuralNetEvaluator::NeuralNetEvaluator(const std::string& config_dir_path, const std::string& config_name) {
        m_config_dir = config_dir_path;
        auto config_dir = fs::path(config_dir_path);
        auto config_path = config_dir / config_name;
        std::ifstream config_stream(config_path);
        json config = json::parse(config_stream);

        m_cc->ClearEvalAutomorphismKeys();
        m_cc->ClearEvalMultKeys();
        m_cc->ClearEvalSumKeys();

        std::string cc_path = config[CC_STRING];

        if (!Serial::DeserializeFromFile(config_path, m_cc, SerType::BINARY)) {
            std::cerr << "I cannot read serialized data from: " << config_dir_path << cc_path << std::endl;
            std::exit(1);
        }

        std::string auto_path = config[AUTO_STRING];
        std::ifstream auto_key_istream(auto_path, std::ios::in | std::ios::binary);

        std::string mult_path = config[MULT_STRING];
        std::ifstream mult_key_istream(mult_path, std::ios::in | std::ios::binary);

        std::string sum_path = config[SUM_STRING];
        std::ifstream sum_key_istream(sum_path, std::ios::in | std::ios::binary);

        if (!mult_key_istream.is_open()) {
            std::cerr << "Cannot read serialization from " << mult_path << std::endl;
            std::exit(1);
        }

        if (!auto_key_istream.is_open()) {
            std::cerr << "Cannot read serialization from " << auto_path << std::endl;
            std::exit(1);
        }

        if (!sum_key_istream.is_open()) {
            std::cerr << "Cannot read serialization from " << sum_path << std::endl;
            std::exit(1);
        }

        m_cc->DeserializeEvalAutomorphismKey(auto_key_istream, SerType::BINARY);
        m_cc->DeserializeEvalMultKey(mult_key_istream, SerType::BINARY);
        m_cc->DeserializeEvalSumKey(auto_key_istream, SerType::BINARY);

        // TODO maybe deserealize public key ? Not needed but who knows...
    }

    CKKSCiphertext NeuralNetEvaluator::load_ciphertext_from_file(const std::string &ct_path) {
        CKKSCiphertext ct;

        if (!Serial::DeserializeFromFile(ct_path, ct, SerType::BINARY)) {
            std::cerr << "Cannot read serialization from " << ct_path << std::endl;
            std::exit(1);
        }

        return ct;
    }

    void NeuralNetEvaluator::write_results(ckks_nn::CKKSCiphertext &ct, std::string& path) {

        if (fs::exists(path)) {
            std::cerr << "File \"" << path << "\" already exists. Exiting...";
            std::exit(-1);
        }

        if (!Serial::SerializeToFile(path, ct, SerType::BINARY)) {
            std::cerr << " Error writing ciphertext 2" << std::endl;
        }
    }

}