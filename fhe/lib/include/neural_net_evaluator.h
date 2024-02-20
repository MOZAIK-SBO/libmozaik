//
// Created by leonard on 2/19/24.
//

#ifndef FHE_NEURAL_NET_EVALUATOR_H
#define FHE_NEURAL_NET_EVALUATOR_H

#include "openfhe.h"
#include "typedefs.h"
#include "neural_net.h"

namespace ckks_nn {

    using namespace lbcrypto;

    struct NeuralNetEvaluator {

        CCParams<CryptoContextCKKSRNS> m_cc_params;
        CryptoContext<DCRTPoly> m_cc;
        KeyPair<DCRTPoly> m_key;
        int_type m_batch_size = 256;


        int_type m_func_degree = 16;

        explicit NeuralNetEvaluator() {

            m_batch_size = 256;
            std::vector<int32_t> automorphism_indices;
            for(int32_t i = 1; i < m_batch_size; i *= 2 ) {
                automorphism_indices.push_back(i);
            }

            m_cc_params.SetMultiplicativeDepth(16);
            m_cc_params.SetScalingModSize(50);
            m_cc_params.SetBatchSize(256);
            m_cc = GenCryptoContext(m_cc_params);
            m_cc->Enable(PKE);
            m_cc->Enable(LEVELEDSHE);
            m_cc->Enable(ADVANCEDSHE);
            m_key = m_cc->KeyGen();

            m_cc->EvalMultKeyGen(m_key.secretKey);
            m_cc->EvalRotateKeyGen(m_key.secretKey, automorphism_indices);
            m_cc->EvalSumKeyGen(m_key.secretKey);
        }

        CKKSCiphertext eval_network(const ckks_nn::NeuralNet &nn, CKKSCiphertext &input);

    private:

        CKKSCiphertext eval_layer(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext eval_mat_mul(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext
        eval_activation(const ckks_nn::NeuralNet &nn, int_type layer_idx, ckks_nn::CKKSCiphertext &vector);

    };


}

#endif //FHE_NEURAL_NET_EVALUATOR_H
