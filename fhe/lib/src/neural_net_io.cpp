//
// Created by leonard on 2/15/24.
//

#ifndef FHE_NEURAL_NET_IO_CPP
#define FHE_NEURAL_NET_IO_CPP

#include <locale>
#include <cassert>
#include <fstream>
#include <algorithm>
#include <iostream>


#include "json.hpp"
#include "neural_net.h"

using json = nlohmann::json;

namespace ckks_nn {

    NeuralNet::NeuralNet(const std::string& config_dir_path, const std::string& config_name) {

        auto config_path = config_dir_path + "/" + config_name;
        std::cout << config_path << std::endl;
        std::ifstream config_stream(config_path);
        json config = json::parse(config_stream);

        int_type n_layers = config["n_layers"];
        m_weights.resize(n_layers);
        m_biases.resize(n_layers);
        m_activations.resize(n_layers);
        m_weight_dims.resize(n_layers);
        m_input_bounds_for_activation.resize(n_layers);

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
            m_weights[layer_idx].resize(rows * cols);
            m_biases[layer_idx].resize(cols);

            // paths to weight / bias matrices
            std::string layer_weight_path = config_dir_path + "/"+ current_layer_config["weight_path"].get<std::string>();
            std::string layer_bias_path = config_dir_path + "/" + current_layer_config["bias_path"].get<std::string>();

            read_weights(layer_weight_path, layer_idx);
            read_biases(layer_bias_path, layer_idx);

            // activation
            std::string activation_str = current_layer_config["activation"];
            auto act = lookup_activation_string(activation_str);
            m_activations[layer_idx] = act;

            auto current_layer_bound = current_layer_config["bounds"];
            assert(current_layer_dim.size() == 2);

            int_type lb = current_layer_bound[0];
            int_type ub = current_layer_bound[1];
            m_input_bounds_for_activation[layer_idx] = {lb, ub};

        }

    }

    void NeuralNet::read_weights(std::string &weight_path, int_type layer) {
        std::ifstream weight_file(weight_path);

        auto rows = m_weight_dims[layer].first;
        auto cols = m_weight_dims[layer].second;

        std::string line_buffer;
        int_type pos = 0;
        for(int_type row = 0; row < rows; row++) {
            std::getline(weight_file, line_buffer);
            std::istringstream line_stream(line_buffer);
            // people claim that this works
            for(int_type col = 0; col < cols; col++) {
                line_stream >> m_weights[layer][pos++];
            }
        }
    }


    void NeuralNet::read_biases(std::string &bias_path, int_type layer) {
        std::cout << bias_path << std::endl;
        std::ifstream bias_stream(bias_path);

        std::string line_buffer;
        int_type pos = 0;
        auto cols = m_weight_dims[layer].second;

        for(int_type col = 0; col < cols; col++) {
            std::getline(bias_stream, line_buffer);

            m_biases[layer][pos++] = std::stod(line_buffer);
        }

        assert(pos == cols);
    }

    NeuralNet::Activation NeuralNet::lookup_activation_string(std::string &activation_string) {
        // why create a string type, but no tolower for the string...
        std::transform(activation_string.begin(), activation_string.end(), activation_string.begin(), ::tolower);
        // switch for strings would also be nice, and its definitely possible, just do a byte for byte comparison with rep (x86)
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
