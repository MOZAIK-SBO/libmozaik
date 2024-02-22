//
// Created by lschild on 20/02/24.
//

#include "neural_net_evaluator.h"
#include "neural_net.h"

namespace ckks_nn {


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

        auto relu_out =  eval_activation(nn, layer_idx, tmp);

        auto keys = m_key;
        Plaintext result;
        m_cc->Decrypt(keys.secretKey, relu_out, &result);
        result->SetLength(m_batch_size);
        std::cout << "Intermediate result is " << result << std::endl;

        return relu_out;
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
                auto tmp = m_cc->EvalChebyshevFunction(func, vector, -1, 1, 2000);
                m_cc->EvalAddInPlace(tmp, vector);
                std::vector<double> d2(m_batch_size);
                std::fill(d2.begin(),d2.end(), 1.0/2);
                auto pt = m_cc->MakeCKKSPackedPlaintext(d2);

                return m_cc->EvalMult(tmp, pt);
            }
            case NeuralNet::Activation::SOFTMAX: {

                // unclean solution for now
                m_cc->EvalSubInPlace(vector, (double) bounds.second);
                double new_lowerbound = bounds.first - bounds.second;
                auto func = [](double x) -> double { return std::exp(x); };
                auto enc_exp = m_cc->EvalChebyshevFunction(func, vector, new_lowerbound, 0, m_func_degree);
                std::vector<double> extract_indices(m_batch_size);
                std::fill(extract_indices.begin(), extract_indices.begin() + dims.second, 1);
                auto extract_ckks = m_cc->MakeCKKSPackedPlaintext(extract_indices);
                auto extracted = m_cc->EvalInnerProduct(enc_exp, extract_ckks, dims.second);
                auto extract_inv = m_cc->EvalDivide(extracted, 0, 1, m_func_degree);
                return m_cc->EvalMult(extract_inv, enc_exp);
            }
            default: break;
        }
        return vector;
    }

}