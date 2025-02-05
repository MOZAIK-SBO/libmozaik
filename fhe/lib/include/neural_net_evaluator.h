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
        uint32_t m_depth;
        KeyPair<DCRTPoly> m_key;
        int_type m_batch_size = 256;
        std::string m_config_dir = ".";

        std::unordered_set<int> rotations_performed;

        explicit NeuralNetEvaluator() {

            m_batch_size = 256;
            auto ring_dim = 1 << 17;

            std::vector<int> automorphism_indices = {50, 49, 48, 47, 46, 45, 44, 43, 42, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, -50, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 100, 41, -200};

            /*
            std::vector<int32_t> automorphism_indices;
            for(int32_t i = 1; i < m_batch_size; i++) {
                automorphism_indices.push_back(i);
                automorphism_indices.push_back(-i);
            } */

            CCParams<CryptoContextCKKSRNS> cc_params;
            cc_params.SetSecretKeyDist(SPARSE_TERNARY);
            cc_params.SetRingDim(ring_dim);
            cc_params.SetSecurityLevel(HEStd_128_classic);

            //cc_params.SetNumLargeDigits(3);
            cc_params.SetBatchSize(ring_dim / 2);

            std::vector<uint32_t> levelBudget = {5, 4};

            int dcrtBits               = 59;
            int firstMod               = 60; //45: 4.XX - 48: 7.84 - 51: 8.07:

            cc_params.SetScalingModSize(dcrtBits);
            cc_params.SetScalingTechnique(FIXEDAUTO);
            cc_params.SetFirstModSize(firstMod);

            cc_params.SetMultiplicativeDepth(36);

            m_cc = GenCryptoContext(cc_params);


            m_cc->Enable(PKE);
            m_cc->Enable(LEVELEDSHE);
            m_cc->Enable(ADVANCEDSHE);
            m_cc->Enable(KEYSWITCH);
            //m_cc->Enable(FHE);

            //m_cc->EvalBootstrapSetup(levelBudget, {0,0}, m_batch_size);

            m_key = m_cc->KeyGen();

            m_cc->EvalMultKeyGen(m_key.secretKey);
            m_cc->EvalRotateKeyGen(m_key.secretKey, automorphism_indices);
            m_cc->EvalSumKeyGen(m_key.secretKey);
            std::cout << "Finished writing sum keys" << std::endl;
            //m_cc->EvalBootstrapKeyGen(m_key.secretKey, m_batch_size);
            //std::cout << "Finished generation BS keys" << std::endl;

        }

        explicit NeuralNetEvaluator(const std::string& config_dir, const std::string& config_name = "crypto_config.json");

        CKKSCiphertext eval_network(const ckks_nn::NeuralNet &nn, CKKSCiphertext &input);

        CKKSCiphertext eval_layer(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext eval_mat_mul(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext eval_mat_mul_square(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext eval_mat_mul_rect(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext MirrorCTForLayer(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext PerformReductionForLayer(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext EvalMVMany(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& packed_vectors);

        CKKSCiphertext EvalLayerMany(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& packed_vectors);

        std::vector<Plaintext> GenerateVectorsForMV(const NeuralNet& nn, int_type layer_idx);

        CKKSCiphertext
        eval_activation(const ckks_nn::NeuralNet &nn, int_type layer_idx, ckks_nn::CKKSCiphertext &vector);

        static NeuralNet build_nn_from_crypto_config(const std::string& config_dir_path, const std::string& config_name = "crypto_config.json");

        static CKKSCiphertext load_ciphertext_from_file(const std::string& ct_path);

        void decrypt_and_print(CKKSCiphertext& ct, uint32_t len);

        static void write_results(CKKSCiphertext& ct, std::string& out_path);

        ~NeuralNetEvaluator() = default;

    };


}

#endif //FHE_NEURAL_NET_EVALUATOR_H
