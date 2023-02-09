#!/usr/bin/env python
from __future__ import print_function

from os.path import isfile

from torchvision import datasets, transforms
import pickle
import sys

import torch
import torch.utils.data
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
        self.optimizer = optim.SGD(self.parameters(), lr=args.lr, momentum=args.momentum)
        self._grads = {}

    def forward(self, x):
        x = F.relu(F.max_pool2d(self.conv1(x), 2))
        x = F.relu(F.max_pool2d(self.conv2_drop(self.conv2(x)), 2))
        x = x.view(-1, 320)
        x = F.relu(self.fc1(x))
        x = F.dropout(x, training=self.training)
        x = self.fc2(x)
        return F.log_softmax(x, dim=1)

def aggregate(model, grads, nGrads):
    optimizer = model.optimizer
    model._grads[nGrads % 3] = grads

    if nGrads % 3 == 0: #model.curr_update_size >= model.update_size:
        for key, gs in model._grads.items():
            for name, param in model.named_parameters():
                worker_grads = [grad[name] for grad in gs]
                param.grad = sum(worker_grads)

        optimizer.step()
        optimizer.zero_grad()
        model._grads = {}

    torch.save(model.state_dict(), 'model.pt')


    if nGrads % 15 == 0:
        test_loader = torch.utils.data.DataLoader(
            datasets.MNIST('../data', train=False, download=True,
                           transform=transforms.Compose([
                               transforms.ToTensor(),
                               transforms.Normalize((0.1307,), (0.3081,))
                           ])),
            batch_size=32, shuffle=True)
        get_accuracy(test_loader, model)
    return

def get_accuracy(test_loader, model):
    model.eval()
    correct_sum = 0
    # Use GPU to evaluate if possible
    device = torch.device("cpu")
    with torch.no_grad():
        for i, (data, target) in enumerate(test_loader):
            out = model(data)
            pred = out.argmax(dim=1, keepdim=True)
            pred, target = pred.to(device), target.to(device)
            correct = pred.eq(target.view_as(pred)).sum().item()
            correct_sum += correct

    print(f"Accuracy {correct_sum / len(test_loader.dataset)}")

def main():
    model = Net()
    if isfile('model.pt'):
        model_dict = torch.load('model.pt')
        model.load_state_dict(model_dict)

    if len(sys.argv) > 1:
        rFile = open('temp.pt', 'rb')
        contents = rFile.read()
        tempGrads = pickle.loads(contents)
        aggregate(model, [tempGrads], int(sys.argv[2]))
    else:
        torch.save(model.state_dict(), 'model.pt')


if __name__ == "__main__":
    main()