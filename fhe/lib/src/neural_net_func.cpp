//
// Created by leonard on 2/15/24.
//
#include <cmath>
#include "neural_net.h"

namespace ckks_nn {

    double NeuralNet::get_weight(ckks_nn::int_type layer, ckks_nn::int_type row, ckks_nn::int_type col) const {
        return m_weights[layer][row * m_weight_dims[layer].second + col];
    }

    double NeuralNet::get_bias(ckks_nn::int_type layer, ckks_nn::int_type row) const {
        return m_biases[layer][row];
    }

    std::vector<double> NeuralNet::get_weight_row(ckks_nn::int_type layer, ckks_nn::int_type row) const {
        auto n_cols = m_weight_dims[layer].second;
        std::vector<double> weight_row(n_cols);
        std::copy(m_weights[layer].begin() + row * n_cols, m_weights[layer].begin() + (row + 1) * n_cols, weight_row.begin());

        return weight_row;
    }

    std::vector<double> NeuralNet::get_weight_col(ckks_nn::int_type layer, ckks_nn::int_type col) const {
        auto n_cols = m_weight_dims[layer].second;
        auto n_rows = m_weight_dims[layer].first;
        std::vector<double> weight_col(n_rows);
        // indices start at 0
        for(int_type idx = 0; idx < n_rows; idx++) {
            weight_col[idx] = m_weights[layer][col + idx * n_cols];
        }

        return weight_col;
    }

    NeuralNet::Activation NeuralNet::get_activation(ckks_nn::int_type layer) const {
        return m_activations[layer];
    }

    int_type NeuralNet::get_n_layers() const {
        return m_weights.size();
    }

    std::pair<int_type, int_type> NeuralNet::get_weight_dim(ckks_nn::int_type idx) const {
        return m_weight_dims[idx];
    }

    std::vector<double> NeuralNet::get_bias_vector(ckks_nn::int_type layer) const {
        return m_biases[layer];
    }

    std::pair<int_type, int_type> NeuralNet::get_bounds(int_type layer) const {
        return m_input_bounds_for_activation[layer];
    }

    int_type NeuralNet::estimate_multiplicative_depth(ckks_nn::int_type func_degree) {

        const int_type COST_MULT = 1;
        const int_type COST_MERGE_SINGLE = 1;
        int_type FUNC_COST = func_degree < 64 ? 7 : 12;
        auto COST_INNER_PROD = COST_MULT;

        int_type depth = 0;
        for(int_type i = 0; i < m_weight_dims.size(); i++) {
            depth += COST_INNER_PROD;
            depth += COST_MERGE_SINGLE;
            if (i == m_weight_dims.size() - 1) {
                depth += FUNC_COST;
                depth += COST_INNER_PROD;
                depth += FUNC_COST;
                depth += COST_MULT;
            } else {
                depth += FUNC_COST;
            }
        }

        return depth;
    }
}