//
// Created by leonard on 2/26/24.
//

#include <iostream>
#include <fstream>
#include <filesystem>

#include "json.hpp"
#include "openfhe.h"
#include "typedefs.h"

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
        std::cerr << "Usage: ./iot_protect [CRYPTO_CONTEXT] [PUBLIC_KEY] [DATA_FILE] [OUTPUT_FILE]" << std::endl;
        std::exit(0);
    }

    CryptoContext<DCRTPoly> m_cc;
    KeyPair<DCRTPoly> m_key;

    m_cc->ClearEvalSumKeys();
    m_cc->ClearEvalMultKeys();
    m_cc->ClearEvalAutomorphismKeys();

    auto cc_path = fs::path(argv[1]);
    auto public_kay_path = fs::path(argv[2]);
    auto data_path = fs::path(argv[3]);
    auto res_path = fs::path(argv[4]);

    // validate paths and deserialize
    if (!fs::exists(cc_path)){
        std::cerr << "Crypto context path does not exist. Exiting..." << std::endl;
        std::exit(-1);
    }

    if (!fs::exists(public_kay_path)){
        std::cerr << "Public key path does not exist. Exiting..." << std::endl;
        std::exit(-1);
    }

    if (!fs::exists(data_path)){
        std::cerr << "Data path does not exist. Exiting..." << std::endl;
        std::exit(-1);
    }

    if(!Serial::DeserializeFromFile(cc_path, m_cc, SerType::BINARY)) {
        std::cerr << "Could not deserialize crypto context. Exiting..." << std::endl;
        std::exit(-1);
    }

    if (!Serial::DeserializeFromFile(public_kay_path, m_key.publicKey, SerType::BINARY)) {
        std::cerr << "Could not deserialize public key. Exiting..." << std::endl;
        std::exit(-1);
    }

    auto data = read_data(data_path, m_cc->GetCyclotomicOrder() / 2);

    // encrypt
    auto encode_pt = m_cc->MakeCKKSPackedPlaintext(data);
    auto ct = m_cc->Encrypt(m_key.publicKey, encode_pt);

    if (!Serial::SerializeToFile(res_path, ct, SerType::BINARY)) {
        std::cerr << "Couldn't serialize output :((( " << std::endl;
        std::exit(-1);
    }

}