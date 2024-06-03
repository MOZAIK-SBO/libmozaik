import numpy as np
import pandas as pd

def load_weight(idx):
    mat = pd.read_csv(f"weights_{idx}_relu.txt",sep=r"\s+",header=None)
    return mat.to_numpy().T

def load_bias(idx):
    return pd.read_csv(f"biases_{idx}_relu.txt",header=None).to_numpy().squeeze()


def eval_net(v_in):
    weights = []
    biases = []
    for i in range(5):
        weights.append(load_weight(i))
        biases.append(load_bias(i))

    inter = v_in
    for i in range(4):
        inter = weights[i] @ inter + biases[i]
        inter[inter < 0] = 0
    inter = weights[-1] @ inter + biases[-1]
    # no softmax for now
    return inter