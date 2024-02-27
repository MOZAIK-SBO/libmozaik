//
// Created by leonard on 2/19/24.
//

#ifndef FHE_NEURAL_NET_EVALUATOR_H
#define FHE_NEURAL_NET_EVALUATOR_H

#include "openfhe.h"
#include "typedefs.h"
#include "neural_net.h"
#include <string>

namespace ckks_nn {

    using namespace lbcrypto;

    struct NeuralNetEvaluator {


        CryptoContext<DCRTPoly> m_cc;
        KeyPair<DCRTPoly> m_key;
        int_type m_batch_size = 256;
        int_type m_func_degree = 16;
        std::string m_config_dir = ".";

        explicit NeuralNetEvaluator() {

            std::vector<int32_t> automorphism_indices;
            for(int32_t i = 1; i < m_batch_size; i++) {
                automorphism_indices.push_back(-i);
            }

            CCParams<CryptoContextCKKSRNS> cc_params;
            cc_params.SetMultiplicativeDepth(100);
            cc_params.SetScalingModSize(59);
            cc_params.SetBatchSize(256);
            cc_params.SetSecurityLevel(HEStd_NotSet);
            cc_params.SetRingDim(512);

            m_cc = GenCryptoContext(cc_params);
            m_cc->Enable(PKE);
            m_cc->Enable(LEVELEDSHE);
            m_cc->Enable(ADVANCEDSHE);
            m_key = m_cc->KeyGen();

            m_cc->EvalMultKeyGen(m_key.secretKey);
            m_cc->EvalRotateKeyGen(m_key.secretKey, automorphism_indices);
            m_cc->EvalSumKeyGen(m_key.secretKey);
        }

        explicit NeuralNetEvaluator(const std::string& config_dir, const std::string& config_name = "crypto_config.json");

        CKKSCiphertext eval_network(const ckks_nn::NeuralNet &nn, CKKSCiphertext &input);

        CKKSCiphertext eval_layer(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext eval_mat_mul(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext
        eval_activation(const ckks_nn::NeuralNet &nn, int_type layer_idx, ckks_nn::CKKSCiphertext &vector);

        static NeuralNet build_nn_from_crypto_config(const std::string& config_dir_path, const std::string& config_name = "crypto_config.json");

        static CKKSCiphertext load_ciphertext_from_file(const std::string& ct_path);

        static void write_results(CKKSCiphertext& ct, std::string& out_path);

        ~NeuralNetEvaluator() = default;

    };


}

#endif //FHE_NEURAL_NET_EVALUATOR_H
