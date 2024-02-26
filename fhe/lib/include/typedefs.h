//
// Created by leonard on 2/19/24.
//

#ifndef FHE_TYPEDEFS_H
#define FHE_TYPEDEFS_H

#include "openfhe.h"

namespace ckks_nn {

    using namespace lbcrypto;

    using CKKSCiphertext = Ciphertext<DCRTPoly>;

    const std::string CC_STRING = "crypto_context";
    const std::string PUB_STRING = "public_key";
    const std::string SK_STRING = "secret_key";
    const std::string AUTO_STRING ="automorphism_key";
    const std::string SUM_STRING = "sum_key";
    const std::string MULT_STRING = "mult_key";
    const std::string NN_STRING = "neural_network_config";

}

#endif //FHE_TYPEDEFS_H
