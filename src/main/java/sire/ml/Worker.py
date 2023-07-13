import random

import numpy as np
import tensorflow.compat.v1 as tf
import sys
import pickle, socket, codecs
import messages_pb2
from random import sample

tf.disable_v2_behavior()

class WorkerType:
    Correct = 1
    Byzantine = 2

def linear_regression(worker_type, X, y, learning_rate=0.1, num_iterations=10, initial_theta=None):
    if initial_theta is None:
        theta = tf.Variable(tf.zeros([2, 1]), dtype=tf.float32)
    else:
        theta = tf.Variable(initial_theta, dtype=tf.float32)
    X_ph = tf.placeholder(tf.float32, shape=[None, 2])
    y_ph = tf.placeholder(tf.float32, shape=[None])

    # Define the model and cost function
    y_hat = tf.squeeze(tf.matmul(X_ph, theta))
    cost = tf.reduce_mean(tf.square(y_hat - y_ph)) / 2

    # Define the optimizer and training operation
    optimizer = tf.train.GradientDescentOptimizer(learning_rate)
    train_op = optimizer.minimize(cost)

    # Initialize the session and variables
    sess = tf.Session()
    sess.run(tf.global_variables_initializer())

    # Perform the gradient descent optimization
    for i in range(num_iterations):
        feed_dict = {X_ph: X, y_ph: y}
        _, cost_val, theta_val = sess.run([train_op, cost, theta], feed_dict=feed_dict)

    if worker_type == WorkerType.Correct:
        return theta_val
    else:
        return sess.run(tf.cast(tf.random.normal([2, 1], mean=0.0, stddev=1.0), dtype=theta_val.dtype))

if __name__ == '__main__':
    worker_id = int(sys.argv[1])
    worker_type = sys.argv[2]
    num_rounds = int(sys.argv[3])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "localhost"
    port = 2500 + worker_id
    sock.connect((host, port))
    np.random.seed(51)
    X = np.random.rand(100, 2)
    y = np.dot(X, [3, 4]) + np.random.randn(100) * 0.1
    current_theta = None
    for i in range(num_rounds):
        current_theta = linear_regression(worker_type, X, y)
        model_put = messages_pb2.ProxyMessage()
        model_put.deviceId = str(worker_id)
        model_put.appId = "app1"
        model_put.operation = messages_pb2.ProxyMessage.MAP_PUT
        model_put.key = "model"
        print(current)
        model_put.value = codecs.encode(pickle.dumps(current_theta), "base64").decode()
        sock.send

