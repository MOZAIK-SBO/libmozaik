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
        //std::cout << "Layer... 0" << std::endl;
        auto layer_i_out = eval_layer(nn, 0, input);

        for(int_type i=1; i < nn.get_n_layers(); i++) {
            // << "Layer..." << i << std::endl;
            layer_i_out = eval_layer(nn, i, layer_i_out);
        }

        return layer_i_out->Clone();
    }

    CKKSCiphertext NeuralNetEvaluator::eval_layer(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                  ckks_nn::CKKSCiphertext &vector) {

        CKKSCiphertext tmp = eval_mat_mul(nn, layer_idx, vector);

        // add bias
        auto bias_vec = nn.get_bias_vector(layer_idx);
        auto bias_encoded = m_cc->MakeCKKSPackedPlaintext(bias_vec);
        m_cc->EvalAddInPlace(tmp, bias_encoded);

        auto act_res = eval_activation(nn, layer_idx, tmp);
        //// << "L_out activation " << act_res->GetLevel() << std::endl;
        return act_res;// m_cc->EvalBootstrap(act_res,2,13);
    }

    CKKSCiphertext NeuralNetEvaluator::eval_mat_mul(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                          ckks_nn::CKKSCiphertext &vector) {
        // auto dim = nn.get_weight_dim(layer_idx);

        return eval_mat_mul_rect(nn, layer_idx, vector);

        /*
        if (dim.first == dim.second) {
            return eval_mat_mul_square(nn, layer_idx, vector);
        } else {
            return eval_mat_mul_rect(nn, layer_idx, vector);
        } */

    }

    CKKSCiphertext NeuralNetEvaluator::eval_mat_mul_square(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                           ckks_nn::CKKSCiphertext &vector) {
        auto dims = nn.get_weight_dim(layer_idx);
        auto dim = dims.first;

        assert(2 * dim < m_batch_size);
        /* First, we need to mirror the coefficients s.t. we can perform cyclic rotations */
        // Step 1 masking
        std::vector<double> mask(m_batch_size, 0);
        std::fill(mask.begin(), mask.begin() + dim, 1);
        auto mask_ptx = m_cc->MakeCKKSPackedPlaintext(mask);
        auto vector_mask = m_cc->EvalMult(vector, mask_ptx);
        // Step 2 mirror
        auto vector_mirror =  m_cc->EvalAdd(vector_mask, m_cc->EvalRotate(vector_mask, -dim));

        auto row_0 = nn.get_diag_col(layer_idx, 0);
        auto row_0_ptx = m_cc->MakeCKKSPackedPlaintext(row_0);
        auto acc = m_cc->EvalMult(vector_mirror, row_0_ptx);


        // Add correct coefficients in correct slots.
        for(int32_t i = 1; i < dim; i++) {
            std::vector<double> coefs(m_batch_size, 0);

            auto row_i = nn.get_diag_col(layer_idx, i);
            // // << i << " " << row_i[0] << std::flush;
            std::copy(row_i.begin(), row_i.end(), coefs.begin());
            std::copy(row_i.begin(), row_i.begin() + dim, coefs.begin() + dim);

            auto row_ptx = m_cc->MakeCKKSPackedPlaintext(coefs);
            auto mul_res = m_cc->EvalMult(vector_mirror, row_ptx);

            auto rot_vec = m_cc->EvalRotate(mul_res, (dim - i)%dim);

            m_cc->EvalAddInPlace(acc, rot_vec);
        }

        return acc->Clone();
    }

    CKKSCiphertext  NeuralNetEvaluator::eval_mat_mul_rect(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                          ckks_nn::CKKSCiphertext &vector) {
        auto dims = nn.get_weight_dim(layer_idx);
        auto rows = dims.first;
        auto cols = dims.second;
        assert(cols <= rows);


        int32_t rat = rows % cols == 0 ? rows / cols : rows / cols + 1;
        int32_t padded_length = rat * cols;
        assert((cols + padded_length) <= m_batch_size);

        // // << rat << " " << padded_length << std::endl;

        /* First, we need to mirror the coefficients s.t. we can perform cyclic rotations */
        // Step 1 masking
        std::vector<double> mask_rows(m_batch_size, 0);
        std::fill(mask_rows.begin(), mask_rows.begin() + rows, 1);

        std::vector<double> mask_cols(m_batch_size, 0);
        std::fill(mask_cols.begin(), mask_cols.begin() + cols, 1);

        auto mask_row_ptx = m_cc->MakeCKKSPackedPlaintext(mask_rows);
        auto mask_col_ptx = m_cc->MakeCKKSPackedPlaintext(mask_cols);

        auto vector_upto_rows = m_cc->EvalMult(vector, mask_row_ptx);
        auto vector_upto_cols = m_cc->EvalMult(vector, mask_col_ptx);


        m_rot_indices.emplace(-padded_length);
        auto vector_upto_cols_rot = m_cc->EvalRotate(vector_upto_cols, -padded_length);
        auto vector_mirror = m_cc->EvalAdd(vector_upto_rows, vector_upto_cols_rot);

        //// << "Masking done" << std::endl;
        auto row_0 = nn.get_diag_col(layer_idx, 0);
        auto row_0_ptx = m_cc->MakeCKKSPackedPlaintext(row_0);
        auto acc = m_cc->EvalMult(vector_mirror, row_0_ptx);


        // Add correct coefficients in correct slots.
        for(int32_t i = 1; i < cols; i++) {
            std::vector<double> coefs(m_batch_size, 0);

            auto row_i = nn.get_diag_col(layer_idx, i);
            // // << i << " " << row_i[0] << std::flush;
            std::copy(row_i.begin(), row_i.end(), coefs.begin());
            std::copy(row_i.begin(), row_i.begin() + cols, coefs.begin() + padded_length);

            auto row_ptx = m_cc->MakeCKKSPackedPlaintext(coefs);
            auto mul_res = m_cc->EvalMult(vector_mirror, row_ptx);

            m_rot_indices.emplace((cols - i) % cols);
            auto rot_vec = m_cc->EvalRotate(mul_res, (cols - i)%cols);

            m_cc->EvalAddInPlace(acc, rot_vec);
        }
        // final correction, as the chunks of size \cols need to be added
        uint32_t rat_u = std::abs(rat);

        // check whether ratio of (extended) rows to cols is power of 2, in which case the reduction is trivial
        if ((rat_u & (rat_u - 1)) == 0) {
            for (int32_t i = padded_length / 2; i >= cols; i /= 2) {
                m_rot_indices.emplace(i);
                auto tmp = m_cc->EvalRotate(acc, i);
                m_cc->EvalAddInPlace(acc, tmp);
            }
        } else {
            std::vector<double> cleanup_mask(m_batch_size, 0);
            std::fill(cleanup_mask.begin(), cleanup_mask.begin() + padded_length, 1);
            auto cleanup = m_cc->MakeCKKSPackedPlaintext(cleanup_mask);
            acc = m_cc->EvalMult(acc, cleanup);
            int32_t pow2rat = 1;
            do {
                pow2rat *= 2;
            } while (pow2rat < rat);
            for (int32_t i = cols * pow2rat / 2; i >= cols; i /= 2) {
                m_rot_indices.emplace(i);
                auto tmp = m_cc->EvalRotate(acc, i);
                m_cc->EvalAddInPlace(acc, tmp);
            }
        }
        // // << "yep" << std::endl;
        return acc->Clone();
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
                //// << lb << ub << std::endl;
                auto tmp = m_cc->EvalChebyshevFunction(func, vector, lb, ub, 16);

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
                std::vector<double> normalization(8, 0);
                std::fill(normalization.begin(), normalization.begin() + 5, 1.0 / (2 * std::abs(lb)));
                auto encoded_normalization = m_cc->MakeCKKSPackedPlaintext(normalization);
                // input is between -1, 1 now
                auto normalized = m_cc->EvalMult(vector, encoded_normalization);
                // shift by 2 to prevent approximation error (nan) around 0
                m_cc->EvalAddInPlace(normalized, 1);

                std::vector<double> exp_F = {1, 1, 0.5, 1.0/6};
                auto exp_norm = m_cc->EvalPolyLinear(normalized,exp_F);

                auto sum_exp_norm = m_cc->EvalSum(exp_norm, 5);

                auto log_F = [](double x) {return std::log(x); };
                auto sum_exp_norm_log = m_cc->EvalChebyshevFunction(log_F, sum_exp_norm, 5 * std::exp(1), 5 * std::exp(3), 32
                );

                return m_cc->EvalSub(normalized, sum_exp_norm_log); */            }

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

        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

        std::string cc_path = config[CC_STRING];

        // << cc_path << std::endl;
        if (!Serial::DeserializeFromFile(cc_path, m_cc, ser_type)) {
            std::cerr << "I cannot read serialized data from: " << config_dir_path << cc_path << std::endl;
            std::exit(1);
        }

        std::string auto_path = config[AUTO_STRING];
        std::ifstream auto_key_istream(auto_path, std::ios::in | std::ios::binary);

        std::string mult_path = config[MULT_STRING];
        std::ifstream mult_key_istream(mult_path, std::ios::in | std::ios::binary);

        //std::string sum_path = config[SUM_STRING];
        //std::ifstream sum_key_istream(sum_path, std::ios::in | std::ios::binary);

        if (!mult_key_istream.is_open()) {
            std::cerr << "Cannot read serialization from " << mult_path << std::endl;
            std::exit(1);
        }

        if (!auto_key_istream.is_open()) {
            std::cerr << "Cannot read serialization from " << auto_path << std::endl;
            std::exit(1);
        }

        /*
        if (!sum_key_istream.is_open()) {
            std::cerr << "Cannot read serialization from " << sum_path << std::endl;
            std::exit(1);
        }*/

        m_cc->DeserializeEvalAutomorphismKey(auto_key_istream, ser_type);
        m_cc->DeserializeEvalMultKey(mult_key_istream, ser_type);
        ////std::cout << m_cc->DeserializeEvalSumKey(sum_key_istream, ser_type) << std::endl;
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

        if (!Serial::SerializeToFile(path + ".json", ct, SerType::JSON)) {
            std::cerr << " Error writing ciphertext 2" << std::endl;
        }
    }

}