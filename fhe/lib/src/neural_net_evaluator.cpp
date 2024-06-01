//
// Created by lschild on 20/02/24.
//

#include "neural_net_evaluator.h"
#include "neural_net.h"
#include "json.hpp"
#include "typedefs.h"

#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"


#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

const auto ser_type = lbcrypto::SerType::JSON;

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
        return ret;
    }

    // End cursed
    CKKSCiphertext NeuralNetEvaluator::eval_network(const ckks_nn::NeuralNet &nn, CKKSCiphertext &input) {
        std::cout << 0 << std::endl;
        auto layer_i_out = eval_layer(nn, 0, input);


        for(int_type i=1; i < nn.get_n_layers(); i++) {
            std::cout << i << std::endl;
            layer_i_out = eval_layer(nn, i, layer_i_out);
        }

        return layer_i_out->Clone();
    }

    CKKSCiphertext NeuralNetEvaluator::eval_layer(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                  ckks_nn::CKKSCiphertext &vector) {

        CKKSCiphertext tmp = eval_mat_mul(nn, layer_idx, vector);
        std::cout << "L_out matmul " << vector->GetLevel() << std::endl;


        // add bias
        auto bias_vec = nn.get_bias_vector(layer_idx);
        auto bias_encoded = m_cc->MakeCKKSPackedPlaintext(bias_vec);
        //m_cc->EvalAddInPlace(tmp, bias_encoded);

        //auto act_res = eval_activation(nn, layer_idx, tmp);
        //std::cout << "L_out activation " << act_res->GetLevel() << std::endl;
        return tmp->Clone();//m_cc->EvalBootstrap(act_res,2,13);
    }

    CKKSCiphertext NeuralNetEvaluator::eval_mat_mul(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                          ckks_nn::CKKSCiphertext &vector) {
        auto dim = nn.get_weight_dim(layer_idx);

        if (dim.first == dim.second) {
            return eval_mat_mul_square(nn, layer_idx, vector);
        }


        auto cols = dim.second;

        //std::vector<double> row(m_batch_size);
        std::vector<CKKSCiphertext> temp_results;
        for(int_type i = 0; i < cols; i++) {
            std::cout << i << " " << std::flush;
            auto row_i = nn.get_weight_col(layer_idx, i);
            auto row_ptx = m_cc->MakeCKKSPackedPlaintext(row_i);
            auto inner_prod = m_cc->EvalInnerProduct(vector, row_ptx, m_batch_size);
            temp_results.push_back(inner_prod);
        }
        std::cout << std::endl;

        return m_cc->EvalMerge(temp_results);
    }

    CKKSCiphertext NeuralNetEvaluator::eval_mat_mul_square(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                           ckks_nn::CKKSCiphertext &vector) {
        auto dims = nn.get_weight_dim(layer_idx);
        auto dim = dims.first;

        std::vector<CKKSCiphertext> temp_results;
        for(int32_t i = 0; i < dim; i++) {
            std::cout << i << std::endl;
            auto row_i = nn.get_diag_col(layer_idx, i);
            auto row_ptx = m_cc->MakeCKKSPackedPlaintext(row_i);
            if (i > 0) {
                auto rot_vec = m_cc->EvalRotate(vector, -i);
                temp_results.push_back(m_cc->EvalMult(rot_vec, row_ptx));
            } else {
                temp_results.push_back(m_cc->EvalMult(vector, row_ptx));
            }
        }
        return m_cc->EvalAddManyInPlace(temp_results);
    }

    CKKSCiphertext  NeuralNetEvaluator::eval_mat_mul_rect(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                          ckks_nn::CKKSCiphertext &vector) {
        auto dims = nn.get_weight_dim(layer_idx);
        auto rows = dims.first;
        auto cols = dims.second;
        assert(cols < rows);

        auto padded_length = cols * (rows / cols + 1);
        std::vector<double> full_vec(m_batch_size, 0);

        // TODO, for now we assume cols < rows
        std::vector<CKKSCiphertext> temp_results;
        for(int32_t idx = 0; idx < cols; idx++) {
            std::fill(full_vec.begin(), full_vec.end(), 0.0);
            auto row_i = nn.get_diag_col(layer_idx, idx);
            std::copy(row_i.begin(), row_i.end(), full_vec.begin());
            auto tmp_ct = vector->Clone();
            for(int_type offset = 0; offset < padded_length; offset+=cols) {
                std::vector<double> masked_vector(m_batch_size, 0);
                std::copy(masked_vector.begin() + offset, masked_vector.begin() + (offset + cols), masked_vector.begin());

            }
        }


        for(int_type offset = 0; offset < padded_length; offset+=cols) {
            auto idx = offset / cols;





            auto row_ptx = m_cc->MakeCKKSPackedPlaintext(full_vec);
            temp_results.push_back(m_cc->EvalMult(vector, row_ptx));
        }
        auto pre_rot_ct = m_cc->EvalAddManyInPlace(temp_results);
        /*
        // gives the closest multiple of rows to cols
        int32_t first_rot = padded_length / 2;
        for(int32_t i = first_rot; i >= rows; i >>= 2) {
            std::cout << i << std::endl;
            auto swapped = m_cc->EvalRotate(pre_rot_ct, -i);
            m_cc->EvalAddInPlace(pre_rot_ct, swapped);
        } */
        return pre_rot_ct->Clone();
    }

    CKKSCiphertext
    NeuralNetEvaluator::eval_activation(const ckks_nn::NeuralNet &nn, int_type layer_idx,
                                        ckks_nn::CKKSCiphertext &vector) {
        auto activation = nn.get_activation(layer_idx);
        auto bounds = nn.get_bounds(layer_idx);
        auto lb = static_cast<double>(bounds.first);
        auto ub = static_cast<double>(bounds.second);
        auto dims = nn.get_weight_dim(layer_idx);

        switch (activation) {
            case NeuralNet::Activation::RELU: {

                auto func = [](double x) -> double { return x > 0 ? x : -x;};
                std::cout << lb << ub << std::endl;
                auto tmp = m_cc->EvalChebyshevFunction(func, vector, lb, ub, 32);

                return m_cc->EvalAdd(vector, tmp);
            }
            case NeuralNet::Activation::SOFTMAX_LINEAR: {


                // TODO: implement linearization of softmax around [0,0...,0]
                std::vector<double> F_0(5, 0.2);
                auto encoded_F_0 = m_cc->MakeCKKSPackedPlaintext(F_0);

                // start with 1st order approx
                auto grad_mat = setup_matrix_for_mult(grad_softmax_at_0);
                auto scal = m_cc->MakeCKKSPackedPlaintext(grad_mat[0]);
                auto grad_part = m_cc->EvalMult(vector, scal);

                for(int i = 1; i < 5; i++) {
                    auto tmp = m_cc->MakeCKKSPackedPlaintext(grad_mat[i]);
                    auto prod_i = m_cc->EvalMult(vector, tmp);
                    m_cc->EvalAddInPlace(grad_part, prod_i);
                }

                // now second order
                std::vector<CKKSCiphertext> hessian_rhs;
                for(int i = 0; i < 5; i++) {
                    auto hessian_mat = setup_matrix_for_mult(hessian_softmax_at_0[i]);
                    auto scal_hessian = m_cc->MakeCKKSPackedPlaintext(hessian_mat[0]);
                    auto hessian_part = m_cc->EvalMult(vector, scal_hessian);

                    for(int j = 1; j < 5; j++) {
                        auto tmp = m_cc->MakeCKKSPackedPlaintext(hessian_mat[i]);
                        auto prod_i = m_cc->EvalMult(vector, tmp);
                        m_cc->EvalAddInPlace(hessian_part, prod_i);
                    }
                    auto dotP = m_cc->EvalInnerProduct(hessian_part, vector, 5);
                    hessian_rhs.push_back(dotP);
                }
                auto merged = m_cc->EvalMerge(hessian_rhs);
                m_cc->EvalAddInPlace(merged, grad_part);

                return m_cc->EvalAdd(merged, encoded_F_0);
            }
            case NeuralNet::Activation::SOFTMAX: {
                return vector;
                /*
                // NOTE We compute log-softmax for better stability
                double shift = (lb + ub) / 2;
                // input is between -shift, shift now
                m_cc->EvalSubInPlace(vector, shift);
                lb += shift;
                std::vector<double> normalization(5, 1.0 / std::abs(lb));
                auto encoded_normalization = m_cc->MakeCKKSPackedPlaintext(normalization);
                // input is between -1, 1 now
                auto normalized = m_cc->EvalMult(vector, encoded_normalization);
                // shift by 2 to prevent approximation error (nan) around 0
                m_cc->EvalAddInPlace(normalized, 2);


                std::vector<double> exp_F = {1, 1, 0.5, 1.0/6};
                auto exp_norm = m_cc->EvalPolyLinear(normalized,exp_F);

                auto sum_exp_norm = m_cc->EvalSum(exp_norm, 5);

                auto log_F = [](double x) {return std::log(x); };
                auto sum_exp_norm_log = m_cc->EvalChebyshevFunction(log_F, sum_exp_norm, 5 * std::exp(1), 5 * std::exp(3), 2000);

                return m_cc->EvalSub(normalized, sum_exp_norm_log); */
            }

            default: break;
        }
        return vector;
    }

    NeuralNet NeuralNetEvaluator::build_nn_from_crypto_config(const std::string& config_dir_path, const std::string& config_name) {
        auto config_path = config_dir_path + "/" + config_name;

        std::ifstream config_stream(config_path);
        json config = json::parse(config_stream);


        std::string nn_path_str = config[NN_STRING];
        auto nn_path = fs::path(nn_path_str);
        auto nn_dir = nn_path.parent_path().string();
        auto nn_config = nn_path.filename().string();


        return NeuralNet(nn_dir, nn_config);
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

        std::cout << cc_path << std::endl;
        if (!Serial::DeserializeFromFile(cc_path, m_cc, ser_type)) {
            std::cerr << "I cannot read serialized data from: " << config_dir_path << cc_path << std::endl;
            std::exit(1);
        }

        m_batch_size = m_cc->GetRingDimension() / 2;

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

        std::cout << m_cc->DeserializeEvalAutomorphismKey(auto_key_istream, ser_type) << std::endl;
        std::cout << m_cc->DeserializeEvalMultKey(mult_key_istream, ser_type) << std::endl;
        std::cout << m_cc->DeserializeEvalSumKey(sum_key_istream, ser_type) << std::endl;
    }

    CKKSCiphertext NeuralNetEvaluator::load_ciphertext_from_file(const std::string &ct_path) {
        CKKSCiphertext ct;

        if (!Serial::DeserializeFromFile(ct_path, ct, ser_type)) {
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

        if (!Serial::SerializeToFile(path, ct, ser_type)) {
            std::cerr << " Error writing ciphertext 2" << std::endl;
        }
    }

}