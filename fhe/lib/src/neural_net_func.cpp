//
// Created by leonard on 2/15/24.
//
#include <cmath>
#include <cassert>
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

    std::vector<double> NeuralNet::get_diag_row(ckks_nn::int_type layer, ckks_nn::int_type offset) const {
        auto dims = get_weight_dim(layer);
        auto rows = dims.first;
        auto cols = dims.second;
        std::vector<double> result(cols, 0);
        for(int_type i = 0; i < cols; i++) {
            result[i] = get_weight(layer, (i + offset) % rows, i);
        }
        return result;
    }

    std::vector<double> NeuralNet::get_diag_col(ckks_nn::int_type layer, ckks_nn::int_type offset) const {
        auto dims = get_weight_dim(layer);
        auto rows = dims.first;
        auto cols = dims.second;

        std::vector<double> result(rows, 0);
        for(int_type i = 0; i < rows; i++) {
            result[i] = get_weight(layer, i, (i + offset) % cols);
        }
        return result;
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
        for(int_type i = 0; i < static_cast<int_type>(m_weight_dims.size()); i++) {
            depth += COST_INNER_PROD;
            depth += COST_MERGE_SINGLE;
            if (i == static_cast<int_type>(m_weight_dims.size()) - 1) {
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

    std::vector<double> NeuralNet::eval_layer(ckks_nn::int_type layer_idx, std::vector<double> &vec_in) {

        auto dims = get_weight_dim(layer_idx);
        auto cols = dims.first;
        auto rows = dims.second;

        assert(vec_in.size() == cols);

        // slowest possible implementation
        auto bias = get_bias_vector(layer_idx);

        for(int_type i = 0; i < rows; i++) {
            for(int_type j = 0; j < cols; j++) {
                bias[i] += vec_in[j] * get_weight(layer_idx, j, i);
            }
        }

        auto act = get_activation(layer_idx);

        if (act == Activation::RELU) {
            for(auto& v : bias) {
                v = v > 0 ? v : 0;
            }
        }

        return bias;
    }

    std::vector<double> NeuralNet::eval_net(std::vector<double> &vec_in) {
        auto res = eval_layer(0, vec_in);
        for(int_type i = 1; i < get_n_layers(); i++) {
            res = eval_layer(i, res);
        }

        return res;
    }
}
