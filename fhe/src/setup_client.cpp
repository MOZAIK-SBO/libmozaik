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

void generate_parameter_set_4(fs::path& key_dir, fs::path& nn_config) {

    auto nn_config_path_abs = absolute(fs::path(nn_config));
    std::vector<int> automorphism_indices;
    for(int32_t i = 1; i <= 256; i *= 2) {
        automorphism_indices.push_back(i);
        automorphism_indices.push_back(-i);
        automorphism_indices.push_back(i * 256);
        automorphism_indices.push_back(-i * 256);
    }

    auto n_slots = 1 << 16;;

    CCParams<CryptoContextCKKSRNS> cc_params;
    cc_params.SetSecretKeyDist(SPARSE_TERNARY);
    cc_params.SetRingDim(1 << 17);
    cc_params.SetSecurityLevel(HEStd_128_classic);

    //cc_params.SetNumLargeDigits(3);
    cc_params.SetBatchSize(n_slots);

    int dcrtBits               = 39;
    int firstMod               = 40; //45: 4.XX - 48: 7.84 - 51: 8.07:

    cc_params.SetScalingModSize(dcrtBits);
    cc_params.SetScalingTechnique(FLEXIBLEAUTO);
    cc_params.SetFirstModSize(firstMod);

    auto new_depth = 32;
    cc_params.SetMultiplicativeDepth(new_depth);

    auto cc = GenCryptoContext(cc_params);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(KEYSWITCH);

    auto key = cc->KeyGen();

    cc->EvalMultKeyGen(key.secretKey);
    cc->EvalRotateKeyGen(key.secretKey, automorphism_indices);
    //cc->EvalSumKeyGen(key.secretKey);
    std::cout << "Finished writing sum keys" << std::endl;
    //cc->EvalBootstrapKeyGen(m_key.secretKey, m_batch_size);
    std::cout << "Finished generation BS keys" << std::endl;

    ////// Serialize all keys
    if (!Serial::SerializeToFile(key_dir / CC_STRING, cc, ser_type)) {
        std::cerr << "Error writing serialization of the crypto context to " << (key_dir / CC_STRING).string()
                  << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(key_dir / "crypto_context.json", cc, SerType::JSON)) {
        std::cerr << "Error writing serialization of the crypto context (JSON) to " << (key_dir / CC_STRING).string()
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

    if (!Serial::SerializeToFile(key_dir / "secret_key.json", key.secretKey, SerType::JSON)) {
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

void generate_parameter_set_256(fs::path& key_dir, fs::path& nn_config) {

    auto nn_config_path_abs = absolute(fs::path(nn_config));
    std::vector<int> automorphism_indices = {50, 49, 48, 47, 46, 45, 44, 43, 42, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, -50, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 100, 41, -200};

    // For combining / splitting
    for (int32_t i = 1; i < 256; i *= 2) {
        automorphism_indices.push_back(-i * 256);
        automorphism_indices.push_back(i * 256);
    }

    auto n_slots = 1 << 16;;

    CCParams<CryptoContextCKKSRNS> cc_params;
    cc_params.SetSecretKeyDist(SPARSE_TERNARY);
    cc_params.SetRingDim(1 << 17);
    cc_params.SetSecurityLevel(HEStd_128_classic);

    //cc_params.SetNumLargeDigits(3);
    cc_params.SetBatchSize(n_slots);

    int dcrtBits               = 39;
    int firstMod               = 40; //45: 4.XX - 48: 7.84 - 51: 8.07:

    cc_params.SetScalingModSize(dcrtBits);
    cc_params.SetScalingTechnique(FLEXIBLEAUTO);
    cc_params.SetFirstModSize(firstMod);

    std::vector<uint32_t> levelBudget = {4, 4};
    uint32_t levels_after_bootstrap = 9;

    uint32_t new_depth = levels_after_bootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, SPARSE_TERNARY);
    //std::cerr << new_depth << std::endl;
    cc_params.SetMultiplicativeDepth(new_depth);

    auto cc = GenCryptoContext(cc_params);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    cc->EvalBootstrapSetup(levelBudget, {0,0}, n_slots);

    auto key = cc->KeyGen();

    cc->EvalMultKeyGen(key.secretKey);
    cc->EvalRotateKeyGen(key.secretKey, automorphism_indices);
    //cc->EvalSumKeyGen(key.secretKey);
    std::cout << "Finished writing sum keys" << std::endl;
    cc->EvalBootstrapKeyGen(key.secretKey, n_slots);
    std::cout << "Finished generation BS keys" << std::endl;

    ////// Serialize all keys
    if (!Serial::SerializeToFile(key_dir / CC_STRING, cc, ser_type)) {
        std::cerr << "Error writing serialization of the crypto context to " << (key_dir / CC_STRING).string()
                  << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(key_dir / "crypto_context.json", cc, SerType::JSON)) {
        std::cerr << "Error writing serialization of the crypto context (JSON) to " << (key_dir / CC_STRING).string()
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

    if (!Serial::SerializeToFile(key_dir / "secret_key.json", key.secretKey, SerType::JSON)) {
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


    //// Write JSON config
    json crypto_context;

    auto all_strings = {CC_STRING, AUTO_STRING, SUM_STRING, PUB_STRING, SK_STRING, MULT_STRING, BOOT_STRING};
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

void old_main(int argc, char** argv) {


    std::vector<int32_t> auto_indices = {};

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

    auto m_batch_size = 256;

    std::vector<int32_t> automorphism_indices;
    for(int32_t i = 1; i < m_batch_size; i++) {
        automorphism_indices.push_back(i);
        automorphism_indices.push_back(-i);
    }

    CCParams<CryptoContextCKKSRNS> cc_params;
    cc_params.SetSecretKeyDist(SPARSE_TERNARY);
    cc_params.SetRingDim(1 << 10);
    cc_params.SetSecurityLevel(HEStd_NotSet);

    cc_params.SetNumLargeDigits(3);
    cc_params.SetBatchSize(m_batch_size);

    std::vector<uint32_t> levelBudget = {5, 4};

    int dcrtBits               = 59;
    int firstMod               = 60; //45: 4.XX - 48: 7.84 - 51: 8.07:

    cc_params.SetScalingModSize(dcrtBits);
    cc_params.SetScalingTechnique(FLEXIBLEAUTOEXT);
    cc_params.SetFirstModSize(firstMod);

    uint32_t levels = 50;
    cc_params.SetMultiplicativeDepth(levels);

    auto cc = GenCryptoContext(cc_params);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    //cc->EvalBootstrapSetup(levelBudget, {0,0}, m_batch_size);

    auto key = cc->KeyGen();

    cc->EvalMultKeyGen(key.secretKey);
    cc->EvalRotateKeyGen(key.secretKey, auto_indices);
    //cc->EvalSumKeyGen(key.secretKey);
    std::cout << "Finished writing sum keys" << std::endl;
    //cc->EvalBootstrapKeyGen(m_key.secretKey, m_batch_size);
    std::cout << "Finished generation BS keys" << std::endl;

    ////// Serialize all keys
    if (!Serial::SerializeToFile(key_dir / CC_STRING, cc, ser_type)) {
        std::cerr << "Error writing serialization of the crypto context to " << (key_dir / CC_STRING).string()
                  << std::endl;
        std::exit(1);
    }

    if (!Serial::SerializeToFile(key_dir / "crypto_context.json", cc, SerType::JSON)) {
        std::cerr << "Error writing serialization of the crypto context (JSON) to " << (key_dir / CC_STRING).string()
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

    if (!Serial::SerializeToFile(key_dir / "secret_key.json", key.secretKey, SerType::JSON)) {
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

    /*
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
    } */



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


int main(int argc, char* argv[]) {

    if (argc < 4) {
        std::cerr << "Usage ./setup_client [BATCH_SIZE] [KEY_DIR_TO_BE_CREATED] [PATH_TO_NEURAL_NETWORK_CONFIG_ON_SERVER] " << std::endl;
        std::exit(0);
    }

    int batch_size = std::stoi(argv[1]);
    std::string key_dir_string = argv[2];
    auto key_dir = fs::path(key_dir_string);
    std::string nn_config = argv[3];
    auto nn_config_path_abs = absolute(fs::path(nn_config));

    if (fs::exists(key_dir)) {
        std::cerr << "Key dir already exists. Exiting..." << std::endl;
        std::exit(-1);
    }

    fs::create_directory(key_dir);

    if (batch_size <= 4) {
        generate_parameter_set_4(key_dir, nn_config_path_abs);
    } else {
        generate_parameter_set_256(key_dir, nn_config_path_abs);
    }
}