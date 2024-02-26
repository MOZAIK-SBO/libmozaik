//
// Created by leonard on 2/15/24.
//

#ifndef FHE_NEURAL_NET_H
#define FHE_NEURAL_NET_H

#include <vector>
#include <string>
#include <tuple>
#include <cstdint>

namespace ckks_nn {

    using int_type = std::int64_t;

    struct NeuralNet {

        enum struct Activation {
            RELU,
            SOFTMAX
        };

        explicit NeuralNet(const std::string& config_dir_path = "assets/configs/default/", const std::string& config_name = "config.json");

        double get_weight(int_type layer, int_type row, int_type col) const;

        std::vector<double> get_weight_row(int_type layer, int_type row) const;

        std::vector<double> get_weight_col(int_type layer, int_type col) const;

        double get_bias(int_type layer, int_type row) const;

        std::vector<double> get_bias_vector(int_type layer) const;

        Activation get_activation(int_type layer) const;

        int_type get_n_layers() const;

        std::pair<int_type, int_type> get_bounds(int_type layer) const;

        std::pair<int_type, int_type> get_weight_dim(int_type idx) const;

        int_type estimate_multiplicative_depth(int_type func_degree);

        ~NeuralNet() = default;

    //private:

        std::vector<std::pair<int_type, int_type>> m_input_bounds_for_activation;
        std::vector<std::vector<double>> m_weights;
        std::vector<std::vector<double>> m_biases;
        std::vector<Activation> m_activations;

        std::vector<std::pair<int_type, int_type>> m_weight_dims;

        void read_weights(std::string& weight_path, int_type layer);

        void read_biases(std::string& bias_path, int_type layer);

        static Activation lookup_activation_string(std::string& activation_string);

    };

}

#endif //FHE_NEURAL_NET_H
