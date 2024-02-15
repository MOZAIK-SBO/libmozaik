//
// Created by leonard on 2/15/24.
//
#include "neural_net.h"

namespace ckks_nn {

    double NeuralNet::get_weight(ckks_nn::int_type layer, ckks_nn::int_type row, ckks_nn::int_type col) {
        return m_weights[layer][row * m_weight_dims[layer].second + col];
    }

    double NeuralNet::get_bias(ckks_nn::int_type layer, ckks_nn::int_type row) {
        return m_biases[layer][row];
    }

    std::vector<double> NeuralNet::get_weight_row(ckks_nn::int_type layer, ckks_nn::int_type row) {
        auto n_cols = m_weight_dims[layer].second;
        std::vector<double> weight_row(n_cols);
        std::copy(m_weights[layer].begin() + row * n_cols, m_weights[layer].begin() + (row + 1) * n_cols, weight_row.begin());

        return weight_row;
    }

    std::vector<double> NeuralNet::get_weight_col(ckks_nn::int_type layer, ckks_nn::int_type col) {
        auto n_cols = m_weight_dims[layer].second;
        auto n_rows = m_weight_dims[layer].first;
        std::vector<double> weight_col(n_rows);
        // indices start at 0
        for(int_type idx = 0; idx < n_rows; idx++) {
            weight_col[idx] = m_weights[layer][col + idx * n_cols];
        }

        return weight_col;
    }

    NeuralNet::Activation NeuralNet::get_activation(ckks_nn::int_type layer) {
        return m_activations[layer];
    }

}