from __future__ import print_function

import pickle
from io import BytesIO

import torch, messages_pb2
import torch.utils.data
import torch.nn as nn
import torch.nn.functional as F
import toolz, socket
from torchvision import datasets, transforms
from types import SimpleNamespace
args = SimpleNamespace(batch_size=32, test_batch_size=1000,
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

def train(model, device, data, target):
    #print("Training...")
    model.train()

    data, target = data.to(device), target.to(device)
    output = model(data)
    loss = F.nll_loss(output, target)
    loss.backward()
    return model

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

def worker(device, train_loader, test_loader, sock,
           worker_id=0, num_workers=1,
           iters=20):
    host = "localhost"
    port = 2500 + 1
    sock.connect((host, port))
    _model = None
    # Request to get model

    # sock.send(len(byted).to_bytes(4, byteorder='big'))
    # sock.send(byted)
    #
    # #Receiving model
    # sock.recv(4)
    # bytedSize = sock.recv(4)
    # size = int.from_bytes(bytedSize, "big")
    # res = sock.recv(size)
    # response = messages_pb2.ProxyResponse()
    # response.ParseFromString(res)
    # inp_b = BytesIO(response.value)
    # model_dict = torch.load(inp_b)
    # _model = Net()
    # _model.load_state_dict(model_dict)

    for step in range(0, iters):
        while _model is None:
            model_request = messages_pb2.ProxyMessage()
            model_request.deviceId = str(worker_id)
            model_request.appId = "app1"
            model_request.operation = messages_pb2.ProxyMessage.MAP_GET
            model_request.key = "model"

            # Sending get request
            byted = model_request.SerializeToString()
            bytedSize = len(byted).to_bytes(4, byteorder='big')
            #print(bytedSize)
            sock.send(bytedSize)
            sock.send(byted)
            #print(sock.recv(4))
            bytedSize = sock.recv(4)
            size = int.from_bytes(bytedSize, "big")
            #print(size)
            res = sock.recv(size)
            #print(res)
            response = messages_pb2.ProxyResponse()
            response.ParseFromString(res)
            inp_b = BytesIO(response.value)
            model_dict = torch.load(inp_b)
            _model = Net()
            _model.load_state_dict(model_dict)
        model, _model = _model, None
        param_check = toolz.last(model.parameters())
        check = param_check.detach().numpy().flat[:4]
        print("worker {} iter {}, last params = {}".format(worker_id, step, check))

        data, target = next(iter(train_loader))
        model = train(model, device, data, target)
        grads = {name: p.grad.data for name, p in model.named_parameters()}
        # Request to put gradients
        model_put = messages_pb2.ProxyMessage()
        model_put.deviceId = str(worker_id)
        model_put.appId = "app1"
        model_put.operation = messages_pb2.ProxyMessage.MAP_PUT
        model_put.key = "model"
        model_put.value = pickle.dumps(grads)
        #print(grads)

        # Sending put request
        byted_put = model_put.SerializeToString()
        sock.send(len(byted_put).to_bytes(4, byteorder='big'))
        sock.send(byted_put)

    sock.close()
    get_accuracy(test_loader, model)


def main():
    print("Booting up...")
    device = torch.device("cpu")
    kwargs = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    train_loader = torch.utils.data.DataLoader(
        datasets.MNIST('../data', train=True, download=True,
                       transform=transforms.Compose([
                           transforms.ToTensor(),
                           transforms.Normalize((0.1307,), (0.3081,))
                       ])),
        batch_size=args.batch_size, shuffle=True, **kwargs)
    test_loader = torch.utils.data.DataLoader(
        datasets.MNIST('../data', train=False, download=True,
                       transform=transforms.Compose([
                           transforms.ToTensor(),
                           transforms.Normalize((0.1307,), (0.3081,))
                       ])),
        batch_size=32, shuffle=True)
    worker(device, train_loader, test_loader, sock)


if __name__ == "__main__":
    main()

