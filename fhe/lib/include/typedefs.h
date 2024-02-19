//
// Created by leonard on 2/19/24.
//

#ifndef FHE_TYPEDEFS_H
#define FHE_TYPEDEFS_H

#include "openfhe.h"

namespace ckks_nn {

    using namespace lbcrypto;

    using CKKSCiphertext = Ciphertext<DCRTPoly>;
}

#endif //FHE_TYPEDEFS_H
