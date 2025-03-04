//
// Created by leonard on 5/27/24.
//

#include "openfhe.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

const auto ser_type = SerType::BINARY;

int main() {

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> clientKP;
    Ciphertext<DCRTPoly> ct;

    cc->ClearEvalMultKeys();
    cc->ClearEvalAutomorphismKeys();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

    std::string cc_path = "/home/leonard/PhD/libmozaik/fhe/cmake-build-debug/small_keys/crypto_context";
    std::string ct_path = "/home/leonard/PhD/libmozaik/fhe/cmake-build-debug/ct_cum2";
    std::string sk_path = "/home/leonard/PhD/libmozaik/fhe/cmake-build-debug/small_keys/secret_key";

    auto a = Serial::DeserializeFromFile(cc_path, cc, ser_type);
    auto b = Serial::DeserializeFromFile(ct_path, ct, SerType::BINARY);
    auto c = Serial::DeserializeFromFile(sk_path, clientKP.secretKey, ser_type);

    std::cerr << a << b << c << std::endl;

    Plaintext  pt;
    cc->Decrypt(clientKP.secretKey, ct, &pt);
    pt->SetLength(256);

    std::cout << cc->GetCryptoParameters()->GetElementParams()->GetRingDimension() << std::endl;
    std::cout << pt << std::endl;
}