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
        std::cout << "Layer... 0" << std::endl;
        auto layer_i_out = EvalLayerMany(nn, 0, input);


        for(int_type i=1; i < nn.get_n_layers(); i++) {
            std::cout << "Layer..." << i << std::endl;
            layer_i_out = EvalLayerMany(nn, i, layer_i_out);
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
        //std::cout << "L_out activation " << act_res->GetLevel() << std::endl;
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
            // std::cout << i << " " << row_i[0] << std::flush;
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

        // std::cout << rat << " " << padded_length << std::endl;

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

        auto vector_upto_cols_rot = m_cc->EvalRotate(vector_upto_cols, -padded_length);
        auto vector_mirror = m_cc->EvalAdd(vector_upto_rows, vector_upto_cols_rot);

        //std::cout << "Masking done" << std::endl;
        auto row_0 = nn.get_diag_col(layer_idx, 0);
        auto row_0_ptx = m_cc->MakeCKKSPackedPlaintext(row_0);
        auto acc = m_cc->EvalMult(vector_mirror, row_0_ptx);

        auto digits = m_cc->EvalFastRotationPrecompute(vector_mirror);
        auto M = m_cc->GetCyclotomicOrder();

        // Add correct coefficients in correct slots.
        for(int32_t i = 1; i < cols; i++) {
            std::vector<double> coefs(m_batch_size, 0);

            auto row_i = nn.get_diag_col(layer_idx, i);
            // std::cout << i << " " << row_i[0] << std::flush;
            std::copy(row_i.begin(), row_i.end(), coefs.begin());
            std::copy(row_i.begin(), row_i.begin() + cols, coefs.begin() + padded_length);

            auto row_ptx = m_cc->MakeCKKSPackedPlaintext(coefs);
            auto rot_vec = m_cc->EvalFastRotation(vector_mirror, (cols - i) % cols, M, digits);
            auto mul_res = m_cc->EvalMult(rot_vec, row_ptx);
            //auto mul_res = m_cc->EvalMult(vector_mirror, row_ptx);

            //auto rot_vec = m_cc->EvalRotate(mul_res, (cols - i)%cols);

            m_cc->EvalAddInPlace(acc, mul_res);
        }
        // final correction, as the chunks of size \cols need to be added
        uint32_t rat_u = std::abs(rat);

        // check whether ratio of (extended) rows to cols is power of 2, in which case the reduction is trivial
        if ((rat_u & (rat_u - 1)) == 0) {
            for (int32_t i = padded_length / 2; i >= cols; i /= 2) {
                auto tmp = m_cc->EvalRotate(acc, i);
                m_cc->EvalAddInPlace(acc, tmp);
            }
        } else {
            std::vector<double> cleanup_mask(m_batch_size, 0);
            std::fill(cleanup_mask.begin(), cleanup_mask.begin() + padded_length, 1);
            auto cleanup = m_cc->MakeCKKSPackedPlaintext(cleanup_mask);
            acc = m_cc->EvalMult(acc, cleanup);
            std::cerr << "MUL" << std::endl;
            int32_t pow2rat = 1;
            do {
                pow2rat *= 2;
            } while (pow2rat < rat);
            for (int32_t i = cols * pow2rat / 2; i >= cols; i /= 2) {
                auto tmp = m_cc->EvalRotate(acc, i);
                m_cc->EvalAddInPlace(acc, tmp);
            }
        }
        // std::cout << "yep" << std::endl;
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

                auto func = [](double x) -> double { return x > 0 ? x : 0;};

                return m_cc->EvalChebyshevFunction(func, vector, lb, ub, 64);
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

    CKKSCiphertext NeuralNetEvaluator::EvalMVMany(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                  ckks_nn::CKKSCiphertext &packed_vectors) {

        auto vector_periodic = MirrorCTForLayer(nn, layer_idx, packed_vectors);

        auto matrix_vectors = GenerateVectorsForMV(nn, layer_idx);

        auto accumulator = m_cc->EvalMult(vector_periodic, matrix_vectors.at(0));

        auto M = m_cc->GetCyclotomicOrder();
        auto vector_periodic_digits = m_cc->EvalFastRotationPrecompute(vector_periodic);

        for(int_type vec_idx = 1; vec_idx < matrix_vectors.size(); vec_idx++) {
            auto rotated_vector = m_cc->EvalFastRotation(vector_periodic, vec_idx, M, vector_periodic_digits);
            auto prod = m_cc->EvalMult(rotated_vector, matrix_vectors.at(vec_idx));
            m_cc->EvalAddInPlace(accumulator, prod);
        }

        return PerformReductionForLayer(nn, layer_idx, accumulator);
    }

    CKKSCiphertext
    NeuralNetEvaluator::PerformReductionForLayer(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                 ckks_nn::CKKSCiphertext &vector) {
        auto dim = nn.get_weight_dim(layer_idx);

        auto n_cols = dim.first;
        auto n_rows = dim.second;

        auto poly_dim = m_cc->GetRingDimension() / 2;

        uint32_t col2row_ratio = n_cols % n_rows == 0 ? n_cols / n_rows : n_cols / n_rows + 1;
        uint32_t col2row_ceil = col2row_ratio * n_rows;
        uint32_t block_size = 0;

        CKKSCiphertext clean_vector;

        if ((col2row_ratio & (col2row_ratio - 1)) != 0) {
            auto next_power_of_2 = 1;
            while (next_power_of_2 < col2row_ratio) {
                next_power_of_2 *= 2;
            }
            // If the ratio is a power of two, it's easy
            // If it is not, we round to the next power of two and assume (hope) that next_power_of_2 * n_rows < m_batch_size
            assert(next_power_of_2 * n_rows < m_batch_size);

            // if it is true, we set those redundant slots to zero so that they don't corrupt the actual values

            std::vector<double> redundant_vector(poly_dim, 0);
            std::vector<double> unique_vector(m_batch_size, 0);

            std::fill(unique_vector.begin(), unique_vector.begin() + col2row_ceil, 1);
            for(int_type i = 0; i < poly_dim; i += m_batch_size) {
                std::copy(unique_vector.begin(), unique_vector.end(), redundant_vector.begin() + i);
            }

            auto mask = m_cc->MakeCKKSPackedPlaintext(redundant_vector);

            clean_vector = m_cc->EvalMult(vector, mask);
            block_size = next_power_of_2 * n_rows;
        } else {
            clean_vector = vector;
            block_size = col2row_ceil;
        }

        while (block_size > n_rows) {

            int32_t rotation_amount = block_size / 2;
            auto rotated_vec = m_cc->EvalRotate(clean_vector, rotation_amount);

            m_cc->EvalAddInPlace(clean_vector, rotated_vec);

            block_size /= 2;
        }

        return clean_vector;
    }

    CKKSCiphertext NeuralNetEvaluator::MirrorCTForLayer(const NeuralNet& nn, int_type layer_idx, ckks_nn::CKKSCiphertext &vector) {

        auto dim = nn.get_weight_dim(layer_idx);

        auto n_cols = dim.first;
        auto n_rows = dim.second;

        assert(n_rows <= n_cols);

        auto poly_dim = m_cc->GetRingDimension() / 2;

        // first we set up the masks we use
        // one to clean up the vector
        std::vector<double> scratch_mask(poly_dim, 0);

        // another to get the periodic component
        std::vector<double> period_mask(poly_dim, 0);

        for(int_type i = 0; i < poly_dim; i += m_batch_size) {
            std::fill(scratch_mask.begin() + i, scratch_mask.begin() + i + n_cols, 1);
            std::fill(period_mask.begin() + i, period_mask.begin() + i + n_rows, 1);
        }

        // Move to complex domain
        auto scratch_mask_ptx = m_cc->MakeCKKSPackedPlaintext(scratch_mask);
        auto period_mask_ptx = m_cc->MakeCKKSPackedPlaintext(period_mask);

        // apply masks
        auto period_vector = m_cc->EvalMult(vector, period_mask_ptx);
        auto clean_vector = m_cc->EvalMult(vector, scratch_mask_ptx);

        auto col2row_ratio = n_cols % n_rows == 0 ? n_cols / n_rows : n_cols / n_rows + 1;
        int32_t col2row_ceil = col2row_ratio * n_rows;

        std::cerr << col2row_ratio << " " << col2row_ceil << std::endl;

        auto period_rotated = m_cc->EvalRotate(period_vector, -col2row_ceil);

        return m_cc->EvalAdd(clean_vector, period_rotated);
    }

    CKKSCiphertext NeuralNetEvaluator::EvalLayerMany(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx,
                                                     ckks_nn::CKKSCiphertext &packed_vectors) {

        auto poly_dim = m_cc->GetRingDimension() / 2;

        //std::cerr << "LAYER INPUT" << std::endl;
        //decrypt_and_print(packed_vectors, 256);

        // compute A * v
        auto linear_component = EvalMVMany(nn, layer_idx, packed_vectors);

        // add bias
        std::vector<double> bias = nn.get_bias_vector(layer_idx);
        bias.resize(m_batch_size);

        std::vector<double> bias_repeated(poly_dim, 0);
        for(int_type i = 0; i < poly_dim; i+=m_batch_size) {
            std::copy(bias.begin(), bias.end(), bias_repeated.begin() + i);
        }

        auto bias_ptx = m_cc->MakeCKKSPackedPlaintext(bias_repeated);

        m_cc->EvalAddInPlace(linear_component, bias_ptx);

        auto activated_function = eval_activation(nn, layer_idx, linear_component);

        //std::cerr << "LAYER OUTPUT" << std::endl;
        //decrypt_and_print(activated_function, 256);

        // Generates warning but seems to be BS
        return activated_function;
    }

    std::vector<Plaintext>
    NeuralNetEvaluator::GenerateVectorsForMV(const ckks_nn::NeuralNet &nn, ckks_nn::int_type layer_idx) {

        auto poly_dim = m_cc->GetRingDimension() / 2;
        auto layer_dim = nn.get_weight_dim(layer_idx);

        auto n_cols = layer_dim.first;
        auto n_rows = layer_dim.second;

        auto col2row_ratio = n_cols % n_rows == 0 ? n_cols / n_rows : n_cols / n_rows + 1;
        auto col2row_ceil = col2row_ratio * n_rows;

        assert(col2row_ceil <= m_batch_size);

        std::vector<Plaintext> mv_vectors;

        std::vector<double> unique_vec_buffer(m_batch_size, 0);
        std::vector<double> redundant_vec_buffer(poly_dim, 0);

        for(int_type row_i = 0; row_i < n_rows; row_i++) {

            for(int_type fake_col_i = 0; fake_col_i < col2row_ceil; fake_col_i++) {

                auto weight_row = fake_col_i % n_rows;
                auto weight_col = (fake_col_i + row_i) % col2row_ceil;

                // "temporary" fix. The nn stores the matrix in transposed format, so we flip col and row idx
                auto current_weight = weight_col < n_cols ? nn.get_weight(layer_idx, weight_col, weight_row) : 0;
                unique_vec_buffer[fake_col_i] = current_weight;

            }

            for(int_type block_i = 0; block_i < poly_dim; block_i += m_batch_size) {
                std::copy(unique_vec_buffer.begin(), unique_vec_buffer.end(), redundant_vec_buffer.begin() + block_i);
            }

            auto ptx = m_cc->MakeCKKSPackedPlaintext(redundant_vec_buffer);
            mv_vectors.push_back(ptx);

            std::fill(unique_vec_buffer.begin(), unique_vec_buffer.end(), 0);
            std::fill(redundant_vec_buffer.begin(), redundant_vec_buffer.end(), 0);

        }

        return mv_vectors;

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

    void NeuralNetEvaluator::decrypt_and_print(ckks_nn::CKKSCiphertext &ct, uint32_t len) {
        Plaintext result;

        m_cc->Decrypt(m_key.secretKey, ct, &result);
        result->SetLength(len);

        std::cerr << result << std::endl;
    }
}