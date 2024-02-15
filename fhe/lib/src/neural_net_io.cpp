//
// Created by leonard on 2/15/24.
//

#ifndef FHE_NEURAL_NET_IO_CPP
#define FHE_NEURAL_NET_IO_CPP

#include <locale>
#include <cassert>
#include <fstream>
#include <algorithm>


#include "json.hpp"
#include "neural_net.h"

using json = nlohmann::json;

namespace ckks_nn {

    NeuralNet::NeuralNet(std::string &path) {

        std::ifstream config_stream(path);
        json config = json::parse(config_stream);

        int_type n_layers = config["n_layers"];
        m_weights.reserve(n_layers);
        m_biases.reserve(n_layers);
        m_activations.reserve(n_layers);
        m_weight_dims.reserve(n_layers);

        auto layers = config["layers"];
        assert(layers.size() == n_layers);

        for(int_type layer_idx = 0; layer_idx < n_layers; layer_idx++) {
            // get config for current layer
            auto current_layer_config = layers[layer_idx];

            // dim size for consistency check
            auto current_layer_dim = current_layer_config["dims"];
            assert(current_layer_dim.size() == 2);

            int_type rows = current_layer_dim[0];
            int_type cols = current_layer_dim[1];

            // check that neither dim is <= 0
            assert( (rows > 0) and (cols > 0));

            m_weight_dims[layer_idx] = {rows, cols};
            // could overflow, but in that case we have other problems
            m_weights[layer_idx].reserve(rows * cols);
            m_biases[layer_idx].reserve(rows);

            // paths to weight / bias matrices
            std::string layer_weight_path = current_layer_config["weight_path"];
            std::string layer_bias_path = current_layer_config["bias_path"];

            read_weights(layer_weight_path, layer_idx);
            read_biases(layer_bias_path, layer_idx);

            // activation
            std::string activation_str = current_layer_config["activation"];
            auto act = lookup_activation_string(activation_str);
            m_activations[layer_idx] = act;

        }

    }

    void NeuralNet::read_weights(std::string &weight_path, int_type layer) {
        // TODO
    }


    void NeuralNet::read_biases(std::string &bias_path, int_type layer) {
        // TODO
    }

    NeuralNet::Activation NeuralNet::lookup_activation_string(std::string &activation_string) {
        // why create a string type, but no tolower for the string...
        std::transform(activation_string.begin(), activation_string.end(), activation_string.begin(), ::tolower);
        if (activation_string == "relu") {
            return Activation::RELU;
        }
        if (activation_string == "softmax") {
            return Activation::SOFTMAX;
        }

        throw std::invalid_argument("Activation function not implemented");
    }

}

#endif //FHE_NEURAL_NET_IO_CPP
