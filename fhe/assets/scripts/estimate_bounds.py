import json
from math import floor, ceil
import numpy as np
import pandas as pd

from sympy import exp as sympy_exp
from sympy import symbols, diff

def tensor_to_c_array(tensor):
    try:
        ll = len(tensor)
        body = ", ".join(map(tensor_to_c_array, tensor))
        return "{" + body + "}"
    except TypeError:
        return str(tensor)

def linearize_softmax(a, x_in):
    a = np.array(a)
    x0,x1,x2,x3,x4 = symbols("x0 x1 x2 x3 x4")
    xs = [x0,x1,x2,x3,x4]
    eval_point = dict(zip(xs, a))

    grads = []
    hessians = []

    evaled_grads = []
    evaled_hessians = []
    eval_F = []

    for idx in range(5):
        F = sympy_exp(xs[idx]) / sum(map(sympy_exp, xs))
        grad_F = [diff(F, X) for X in xs]

        hessian_F = []
        for i in range(5):
            row = []
            partial_i = diff(F, xs[i])
            for j in range(5):
                row.append(diff(partial_i, xs[j]))
            hessian_F.append(row)
        grads.append(grad_F)
        hessians.append(hessian_F)

        evaled_grad = np.array([float(gF.subs(eval_point)) for gF in grad_F])
        evaled_hessian = np.array([[float(hF.subs(eval_point)) for hF in hF_row] for hF_row in hessian_F])

        evaled_grads.append(evaled_grad)
        evaled_hessians.append(evaled_hessian)
        eval_F.append(float(F.subs(eval_point)))

    # construct subfunctions
    lin_soft_components = []
    for i in range(5):
        fi = eval_F[i] + (x_in - a) @ evaled_grads[i] + (x_in - a) @ (evaled_hessians[i] @ (x_in - a))
        lin_soft_components.append(fi)


    return grads, hessians, evaled_grads, evaled_hessians, lin_soft_components

def bound_inner_prod(c, l_vec, u_vec):
    l = 0
    u = 0
    for i, ci in enumerate(c):
        test = [ci * l_vec[i], ci * u_vec[i]]
        l += min(test)
        u += max(test)

    return l, u

def bound_mat_mul(mat, l_vec, u_vec):
    l_vec_out = [0] * len(mat)
    u_vec_out = [0] * len(mat)

    for i in range(len(mat)):
        l_vec_out[i],u_vec_out[i] = bound_inner_prod(mat[i], l_vec, u_vec)
    return l_vec_out, u_vec_out

def bound_layer(mat, bias, l_vec, u_vec):
    lv,uv = bound_mat_mul(mat, l_vec, u_vec)
    lv_bias = [a+b for a,b in zip(lv, bias)]
    uv_bias = [a+b for a,b in zip(uv, bias)]
    return lv_bias, uv_bias


def load_file(path_str):
    df = pd.read_csv(path_str, header=None, sep=r"\s+")
    return df.to_numpy()

def fuzz_network(weight_mats, bias_vectors, n=1000):
    minimum_per_layer = pd.DataFrame(columns=["RELU0","RELU1","RELU2","RELU3","SOFTMAX","EXP_OUT","EXP_INV"])
    maximum_per_layer = pd.DataFrame(columns=minimum_per_layer.columns)

    n_init = weight_mats[0].shape[0]
    pd.set_option('display.float_format', '{:.10f}'.format)
    for r in range(n):
        vec = np.random.rand(n_init)
        current_min = []
        current_max = []
        for i,W,b in zip(range(len(weight_mats)), weight_mats, bias_vectors):
            linear_part = vec @ W + b
            current_min.append(np.min(linear_part))
            current_max.append(np.max(linear_part))
            if i < len(weight_mats) - 1:
                vec = np.maximum(linear_part, 0)
            else:
                # linear_part -= 7 - 1
                exp_part = 1 + linear_part + linear_part * linear_part / 2
                current_min.append(np.min(exp_part))
                current_max.append(np.max(exp_part))

                current_min.append(np.min(exp_part * 8))
                current_max.append(np.max(exp_part * 8))

                soft_taylor = exp_part / sum(exp_part)
                soft_max = np.exp(linear_part) / sum(np.exp(linear_part))
                print(soft_max, " | ", soft_taylor)

        minimum_per_layer.loc[r] = current_min
        maximum_per_layer.loc[r] = current_max

    n_stddev = 6
    min_std = n_stddev * minimum_per_layer.std()
    max_std = n_stddev * maximum_per_layer.std()
    min_mean = minimum_per_layer.mean()
    max_mean = maximum_per_layer.mean()

    for c in minimum_per_layer.columns.tolist():
        min_col = minimum_per_layer[c]
        max_col = maximum_per_layer[c]

        min_mean_s = min_col.loc[(min_col < (min_mean[c] + min_std[c])) & (min_col > (min_mean[c] - min_std[c]))].mean()
        max_mean_s = max_col.loc[(max_col < (max_mean[c] + max_std[c])) & (max_col > (max_mean[c] - max_std[c]))].mean()
        print(c, min_mean_s, max_mean_s)

if __name__ == "__main__":
    cfg_dir = "../configs/default/"
    cfg_path = cfg_dir + "config.json"

    layer_mats = []
    bias_mats = []

    with open(cfg_path) as f:
        config = json.load(f)

        input_bounds = config["input_bounds"]
        for layer in config["layers"]:
            wp = cfg_dir + layer["weight_path"]
            bp = cfg_dir + layer["bias_path"]
            dims = layer["dims"]

            with open(wp) as wf:
                layer_mats.append(load_file(wp))

            with open(bp) as bf:
                bias = bf.readlines()
                bias_float = [float(bi.strip()) for bi in bias]
                assert len(bias_float) == dims[1]

                bias_mats.append(np.array(bias_float))
        fuzz_network(layer_mats, bias_mats)
        """
        vec_dim = config["layers"][0]["dims"][0]
        lb = [input_bounds[0]] * vec_dim
        ub = [input_bounds[1]] * vec_dim

        for i in range(config["n_layers"]):
            lbnew, ubnew = bound_layer(layer_mats[i], bias_mats[i], lb, ub)

            js = f"\"bounds\": [{floor(min(lbnew))}, {ceil(max(ubnew))}], "
            print("Bounds to activation function for layer ", i, " : ", js)

            if i != config["n_layers"] - 1:
                lb = [max(a, 0) for a in lbnew]
                ub = [max(a, 0) for a in ubnew]
        """
