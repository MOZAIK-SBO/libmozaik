import json
from math import floor, ceil

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
                weights = []

                for i in range(dims[0]):
                    row = wf.readline()
                    row = row.strip()
                    row_float = [float(rc) for rc in row.split()]
                    assert len(row_float) == dims[1]
                    weights.append(row_float)

                weights = list(map(list, zip(*weights)))
                layer_mats.append(weights)

            with open(bp) as bf:
                bias = bf.readlines()
                bias_float = [float(bi.strip()) for bi in bias]
                assert len(bias_float) == dims[1]

                bias_mats.append(bias_float)

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

