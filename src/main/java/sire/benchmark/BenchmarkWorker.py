import time
import numpy as np
import tensorflow as tf
import sys
import socket
import messages_pb2

class WorkerType:
    Correct = 1
    Byzantine = 2

def linear_regression(worker_type, X, y, learning_rate=0.1, num_iterations=10, initial_theta=None):
    model = tf.keras.Sequential([tf.keras.layers.Dense(1, input_shape=(2,))])
    model.compile(optimizer=tf.optimizers.SGD(learning_rate), loss='mean_squared_error')

    if initial_theta is not None:
        model.set_weights([np.array([[initial_theta[0][0]], [initial_theta[1][0]]]), np.array([0.0])])

    model.fit(X, y, epochs=num_iterations, verbose=0)

    if worker_type == WorkerType.Correct:
        return model.get_weights()[0]
    else:
        return np.random.normal(size=(2, 1), loc=0.0, scale=1.0).astype(np.float32)

if __name__ == '__main__':
    print("Yooooooooooooooooo")
    worker_id = int(sys.argv[1])
    worker_type = 1
    num_rounds = int(sys.argv[3])
    initial_id = int(sys.argv[4])
    measurement_leader = bool(sys.argv[5])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "localhost"
    port = 2500 + worker_id
    sock.connect((host, port))
    np.random.seed(51)
    X = np.random.rand(100, 2)
    y = np.dot(X, [3, 4]) + np.random.randn(100) * 0.1
    current_theta = None
    latencyAvg = 0
    latencyMin = sys.maxsize
    latencyMax = 0
    if worker_id == initial_id:
        if measurement_leader:
            print("I'm measurement leader")
        print("Sending test data...")
    else:
        print("Not measurement leader")

    if worker_id == initial_id:
        print(f'Executing experiment for {num_rounds} ops')
    lat = 0
    for i in range(num_rounds):
        current_theta = linear_regression(worker_type, X, y, initial_theta=current_theta)
        model_put = messages_pb2.ProxyMessage()
        model_put.deviceId = str(worker_id)
        model_put.appId = "app1"
        model_put.operation = messages_pb2.ProxyMessage.MAP_PUT
        model_put.key = "model"
        pass_theta = current_theta.flatten()
        for i in range(len(pass_theta)):
            model_put.theta.append(pass_theta[i])
        if measurement_leader and lat != 0:
            model_put.latency = lat
        byted_put = model_put.SerializeToString()
        t1 = time.time_ns()
        sock.send(len(byted_put).to_bytes(4, byteorder='big'))
        sock.send(byted_put)
        size_response = int.from_bytes(sock.recv(4), byteorder='big')
        sock.recv(size_response)
        t2 = time.time_ns()
        lat = t2 - t1
        if lat < latencyMin:
            latencyMin = lat
        if lat > latencyMax:
            latencyMax = lat
        latencyAvg += lat
