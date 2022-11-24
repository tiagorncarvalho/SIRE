#!/usr/bin/env python
from __future__ import print_function

import pickle, sys

import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F

from types import SimpleNamespace

args = SimpleNamespace(batch_size=64, test_batch_size=1000,
                       epochs=2, lr=0.01, momentum=0.5,
                       no_cuda=True, seed=42, log_interval=80)

class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.conv1 = nn.Conv2d(1, 10, kernel_size=5)
        self.conv2 = nn.Conv2d(10, 20, kernel_size=5)
        self.conv2_drop = nn.Dropout2d()
        self.fc1 = nn.Linear(320, 50)
        self.fc2 = nn.Linear(50, 10)

    def forward(self, x):
        x = F.relu(F.max_pool2d(self.conv1(x), 2))
        x = F.relu(F.max_pool2d(self.conv2_drop(self.conv2(x)), 2))
        x = x.view(-1, 320)
        x = F.relu(self.fc1(x))
        x = F.dropout(x, training=self.training)
        x = self.fc2(x)
        return F.log_softmax(x, dim=1)

def aggregate(pickled_model, grads):
    if pickled_model is None:
        model = Net()
    else:
        model = pickled_model
        print("Model :)\n")
    if len(grads) == 0:
        #with open('model.pickle', 'wb') as handle:
        #    pickle.dump(model, handle, protocol=pickle.HIGHEST_PROTOCOL)
        return
    optimizer = optim.SGD(model.parameters(), lr=args.lr, momentum=args.momentum)
    for name, param in model.named_parameters():
        worker_grads = [grad[name] for grad in grads]
        param.grad = sum(worker_grads)
    optimizer.step()
    optimizer.zero_grad()

    print(pickle.dumps(model))
    return

def main():
    with open('model.pickle', 'rb') as handle:
        model = pickle.load(handle)
        aggregate(model, [])

if __name__ == "__main__":
    main()