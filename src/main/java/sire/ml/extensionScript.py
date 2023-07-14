import random

import numpy as np
import tensorflow.compat.v1 as tf
from random import sample
import sys, pickle, argparse

CLI=argparse.ArgumentParser()
CLI.add_argument(
  "--lista",  # name on the CLI - drop the `--` for positional/required parameters
  nargs="*",  # 0 or more values expected => creates a list
  type=int
)

tf.disable_v2_behavior()

class ParameterServer:
    @staticmethod
    def euclidean_distance(x, y):
        return np.sqrt(np.sum((x - y) ** 2))

    @staticmethod
    def krum(weights, k=2):
        n = len(weights)
        distances = np.zeros((n, n))
        for i in range(n):
            for j in range(i + 1, n):
                distances[i][j] = ParameterServer.euclidean_distance(weights[i], weights[j])
                distances[j][i] = distances[i][j]
        scores = []
        for i in range(n):
            d = sorted(distances[i])
            s = sum(d[1:k + 1])
            scores.append((s, i))
        scores = sorted(scores)
        krum_index = scores[0][1]
        return weights[krum_index]


if __name__ == '__main__':
    args = CLI.parse_args()
    res = ParameterServer.krum([pickle.loads(bytes(args.lista))])
    fl = res.flatten()
    print(fl)