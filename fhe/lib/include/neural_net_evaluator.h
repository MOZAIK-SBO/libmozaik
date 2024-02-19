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

        bool m_smart_mat_mul;

        explicit NeuralNetEvaluator(bool smart_mat_mul) : m_smart_mat_mul(smart_mat_mul) {

        }

    private:

        CKKSCiphertext eval_layer(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext eval_smart_mat_mul(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext eval_mat_mul(const NeuralNet& nn, int_type layer_idx, CKKSCiphertext& vector);

        CKKSCiphertext eval_activation(NeuralNet::Activation activation, CKKSCiphertext& vector);

    };


}

#endif //FHE_NEURAL_NET_EVALUATOR_H
