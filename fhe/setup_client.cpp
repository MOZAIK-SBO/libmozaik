//
// Created by lschild on 20/02/24.
//

#include <iostream>
#include <fstream>
#include <filesystem>

#include "json.hpp"
#include "openfhe.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "typedefs.h"

namespace fs = std::filesystem;
using json = nlohmann::json;
using namespace lbcrypto;
using namespace ckks_nn;

/*
 * We might need to target wasm to be able to encrypt and decrypt results in the browser. Same goes for keygen.
 * Generating the keys somewhere that's not the IOT device or client is pointless
 * so if we run in wasm, we wouldn't actually store the keys on device but rather generate locally in
 * browser, send it correctly to the remote host and store the FHE secret key locally and encrypted using asymmetric
 * crypto somewhere else.
 * Note: WE MUST MAKE THE CLIENT SIDE CODE PUBLIC AND GIVE USERS THE OPTION TO GENERATE THE KEYS THEMSELVES.
 * Otherwise, we could just execute arbitrary code on their device if they have no method to verify the correctness
 * of the key generation process.
 *
 */

const auto ser_type = SerType::JSON;

int main(int argc, char* argv[]) {

    if (argc < 3) {
        std::cerr << "Usage ./setup_client [KEY_DIR_TO_BE_CREATED] [PATH_TO_NEURAL_NETWORK_CONFIG_ON_SERVER] " << std::endl;
        std::exit(0);
    }

    std::string key_dir_string = argv[1];
    auto key_dir = fs::path(key_dir_string);
    std::string nn_config = argv[2];
    auto nn_config_path_abs = absolute(fs::path(nn_config));

    if (fs::exists(key_dir)) {
        std::cerr << "Key dir already exists. Exiting..." << std::endl;
        std::exit(-1);
    }

    fs::create_directory(key_dir);

    int m_batch_size = 256;
    std::vector<int32_t> automorphism_indices;
    for(int32_t i = 1; i < m_batch_size; i++) {
        automorphism_indices.push_back(-i);
    }

    // Generate parameters and keys
    CCParams<CryptoContextCKKSRNS> cc_params;

    // Hardcode for now
    cc_params.SetMultiplicativeDepth(10);
    cc_params.SetScalingModSize(50);
    cc_params.SetBatchSize(256);
    cc_params.SetSecurityLevel(HEStd_NotSet);
    cc_params.SetRingDim(512);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(cc_params);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    auto key = cc->KeyGen();

    cc->EvalMultKeyGen(key.secretKey);
    cc->EvalRotateKeyGen(key.secretKey, automorphism_indices);
    cc->EvalSumKeyGen(key.secretKey);

    ////// Serialize all keys
    if (!Serial::SerializeToFile(key_dir / CC_STRING, cc, ser_type)) {
        std::cerr << "Error writing serialization of the crypto context to " << (key_dir / CC_STRING).string()
                  << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(key_dir / PUB_STRING, key.publicKey, ser_type)) {
        std::cerr << "Error writing public key to " << (key_dir / PUB_STRING).string() << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(key_dir / SK_STRING, key.secretKey, ser_type)) {
        std::cerr << "Error writing secret key to " << (key_dir / SK_STRING).string() << std::endl;
        std::exit(1);
    }

    std::ofstream multKeyFile(key_dir / MULT_STRING, std::ios::out | std::ios::binary);
    if (multKeyFile.is_open()) {
        if (!cc->SerializeEvalMultKey(multKeyFile, ser_type)) {
            std::cerr << "Error writing mult keys" << std::endl;
            std::exit(1);
        }
        multKeyFile.close();
    }
    else {
        std::cerr << "Error serializing mult keys" << std::endl;
        std::exit(1);
    }

    std::ofstream rotationKeyFile(key_dir / AUTO_STRING, std::ios::out | std::ios::binary);
    if (rotationKeyFile.is_open()) {
        if (!cc->SerializeEvalAutomorphismKey(rotationKeyFile, ser_type)) {
            std::cerr << "Error writing automorphism keys" << std::endl;
            std::exit(1);
        }
        rotationKeyFile.close();
    }
    else {
        std::cerr << "Error serializing automorphism keys" << std::endl;
        std::exit(1);
    }

    std::ofstream sumKeyFile(key_dir / SUM_STRING, std::ios::out | std::ios::binary);
    if (sumKeyFile.is_open()) {
        if (!cc->SerializeEvalSumKey(sumKeyFile, ser_type)) {
            std::cerr << "Error writing sum keys" << std::endl;
            std::exit(1);
        }
        sumKeyFile.close();
    }
    else {
        std::cerr << "Error serializing sum keys" << std::endl;
        std::exit(1);
    }

    cc->Ser

    std::ofstream bootKeyFile(key_dir / BOOT_STRING, std::ios::out | std::ios::binary);
    if (bootKeyFile.is_open()) {
        if (!cc->Serialize(sumKeyFile, ser_type)) {
            std::cerr << "Error writing sum keys" << std::endl;
            std::exit(1);
        }
        sumKeyFile.close();
    }
    else {
        std::cerr << "Error serializing sum keys" << std::endl;
        std::exit(1);
    }

    //// Write JSON config
    json crypto_context;

    auto all_strings = {CC_STRING, AUTO_STRING, SUM_STRING, PUB_STRING, SK_STRING, MULT_STRING};
    for (auto& str : all_strings) {
        auto path = key_dir / str;
        auto path_abs_str = absolute(path).string();
        crypto_context[str] = path_abs_str;
    }

    crypto_context[NN_STRING] = nn_config_path_abs.string();

    std::ofstream out(key_dir / "crypto_config.json");
    if (out.is_open()) {
        out << std::setw(4) << crypto_context;
        out.close();
    } else {
        std::cerr << "Couldn't open config file." << std::endl;
        std::exit(-1);
    }

}