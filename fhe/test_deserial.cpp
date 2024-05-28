//
// Created by leonard on 5/27/24.
//

#include "openfhe.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

int main() {
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> clientKP;
    Ciphertext<DCRTPoly> ct;

    cc->ClearEvalMultKeys();
    cc->ClearEvalAutomorphismKeys();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

    std::string cc_path = "/home/leonard/PhD/libmozaik/fhe/build2/test_keys/crypto_context";
    std::string ct_path = "/home/leonard/PhD/libmozaik/fhe/build2/data.ct";
    std::string sk_path = "/home/leonard/PhD/libmozaik/fhe/build2/test_keys/secret_key";

    Serial::DeserializeFromFile(cc_path, cc, SerType::JSON);
    Serial::DeserializeFromFile(ct_path, ct, SerType::JSON);
    Serial::DeserializeFromFile(sk_path, clientKP.secretKey, SerType::JSON);

    Plaintext  pt;
    auto dec = cc->Decrypt(clientKP.secretKey, ct, &pt);
    pt->SetLength(256);

    std::cout << cc->GetCryptoParameters()->GetElementParams()->GetRingDimension() << std::endl;
    std::cout << pt << std::endl;
}