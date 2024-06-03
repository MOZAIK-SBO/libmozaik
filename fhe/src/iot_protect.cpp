//
// Created by leonard on 2/26/24.
//

#include <iostream>
#include <fstream>
#include <filesystem>

#include "json.hpp"
#include "openfhe.h"
#include "typedefs.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

namespace fs = std::filesystem;
using json = nlohmann::json;
using namespace lbcrypto;
using namespace ckks_nn;


// We assume data file are stored with 1 value per line, delimited by \n not \r\n
std::vector<double> read_data(fs::path& data_path, unsigned int length) {
    std::vector<double> ret(length, 0);
    std::ifstream data(data_path);
    std::string token;
    for(int i = 0; i < length; i++) {
        std::getline(data, token);
        if (token.empty())
            break;

        ret[i] = std::stod(token);
    }
    return ret;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: ./iot_protect [CRYPTO_CONTEXT_PATH] [PUBLIC_KEY] [DATA_FILE] [OUTPUT_FILE]" << std::endl;
        std::exit(0);
    }

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> clientKP;
    PublicKey<DCRTPoly> m_key;

    cc->ClearEvalMultKeys();
    cc->ClearEvalAutomorphismKeys();
    cc->ClearEvalSumKeys();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

    auto context_path = fs::path(argv[1]);
    auto public_key_path = fs::path(argv[2]);
    auto data_path = fs::path(argv[3]);
    auto res_path = fs::path(argv[4]);

    if (!fs::exists(context_path)){
        std::cerr << "Public key path does not exist. Exiting..." << std::endl;
        std::exit(-1);
    }

    if (!fs::exists(public_key_path)){
        std::cerr << "Public key path does not exist. Exiting..." << std::endl;
        std::exit(-1);
    }

    if (!fs::exists(data_path)){
        std::cerr << "Data path does not exist. Exiting..." << std::endl;
        std::exit(-1);
    }

    if (!Serial::DeserializeFromFile(context_path, cc, ser_type)) {
        std::cerr << "Could not deserialize crypto context. Exiting..." << std::endl;
        std::exit(-1);
    }

    if (!Serial::DeserializeFromFile(public_key_path, m_key, ser_type)) {
        std::cerr << "Could not deserialize public key. Exiting..." << std::endl;
        std::exit(-1);
    }

    auto data = read_data(data_path, 256);
    // encrypt
    auto encode_pt = cc->MakeCKKSPackedPlaintext(data);

    auto ct = cc->Encrypt(m_key, encode_pt);

    if (!Serial::SerializeToFile(res_path, ct, ser_type)) {
        std::cerr << "Couldn't serialize output :((( " << std::endl;
        std::exit(-1);
    }

}