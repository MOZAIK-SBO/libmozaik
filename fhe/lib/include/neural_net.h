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

        explicit NeuralNet(std::string& path);

        double get_weight(int_type layer, int_type row, int_type col);

        std::vector<double> get_weight_row(int_type layer, int_type row);

        std::vector<double> get_weight_col(int_type layer, int_type col);

        double get_bias(int_type layer, int_type row);

        Activation get_activation(int_type layer);

    private:

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
