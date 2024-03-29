/*
 * Copyright 2023 Tiago Carvalho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sire.benchmark;

import sire.device.DeviceStub;
import sire.membership.DeviceContext;
import sire.messages.Messages;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class LatencyAttestationClient {

    //private static String initialId;
    private static final String appId = "app1";
    private static final String version = "1.0";

    public static void main(String[] args) throws InterruptedException, NoSuchPaddingException, NoSuchAlgorithmException, ClassNotFoundException, IOException {
        if (args.length != 4) {
            System.out.println("USAGE: benchmark.LatencyAttestationClient <initial client id> " +
                    "<num clients> <number of ops> <operation> <measurement leader?>");
            System.exit(-1);
        }
        //initialId = args[0];
        DeviceContext.DeviceType type = DeviceContext.DeviceType.CAMERA;
        byte[] claim = "measure1".getBytes();
        int numClients = Integer.parseInt(args[0]);
        int numOperations = Integer.parseInt(args[1]);
        Messages.ProxyMessage.Operation operation;
        if((operation = operationFromString(args[2])) == null) {
            System.out.println("Couldn't parse operation. Available operations:\n - attest\n - getKey");
            System.exit(-1);
        }

        System.out.println("Operation: " + operation);

        boolean measurementLeader = Boolean.parseBoolean(args[3]);

        Random random = new Random(1L);
        byte[] value = new byte[1024];
        random.nextBytes(value);

        DeviceStub stub = new DeviceStub();
        //stub.attest(appId, type, version, claim);

        Client[] clients = new Client[numClients];
        for (int i = 0; i < numClients; i++) {
            int sleepTime = random.nextInt(2000);
            Thread.sleep(sleepTime);

            if (i > 0) {
                stub = new DeviceStub();
                //stub.attest(appId, type, version, claim);
            }

            String id = Integer.toString(i);
            clients[i] = new Client(Integer.toString(i), stub, numOperations, measurementLeader) {
                @Override
                void sendOperation(DeviceStub stub) {
                    System.out.println("Sending op!");
                    try {
                        switch (operation) {
                            case MEMBERSHIP_JOIN: stub.attest(appId, version, claim);
                            case MAP_PUT: stub.put(appId, id, value);
                            case MAP_GET: stub.getData(appId, "key");
                        }
                    } catch (IOException | ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                }
            };
        }
        ExecutorService executorService = Executors.newFixedThreadPool(numClients);
        Collection<Future<?>> tasks = new LinkedList<>();
        for (Client client : clients) {
            try {
                Thread.sleep(random.nextInt(50));
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            tasks.add(executorService.submit(client));
        }
        Runtime.getRuntime().addShutdownHook(new Thread(executorService::shutdownNow));
        for (Future<?> task : tasks) {
            try {
                task.get();
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
                executorService.shutdownNow();
                System.exit(-1);
            }
        }
        executorService.shutdown();
        System.out.println("Experiment ended");
    }

    private static abstract class Client extends Thread {
        private final String id;
        private final DeviceStub stub;
        private final int numOperations;
        private final boolean measurementLeader;
        private int rampup = 1000;

        Client(String id, DeviceStub stub, int numOperations, boolean measurementLeader) {
            super("Client " + id);
            this.id = id;
            this.stub = stub;
            this.numOperations = numOperations;
            this.measurementLeader = measurementLeader;
        }

        abstract void sendOperation(DeviceStub stub);

        @Override
        public void run() {
            if (id.equals("0")) {
                if (measurementLeader)
                    System.out.println("I'm measurement leader");
                System.out.println("Sending test data...");
            }
            sendOperation(stub);
            if (id.equals("0")) {
                System.out.println("Executing experiment for " + numOperations + " ops");
            }
            for (int i = 1; i < numOperations; i++) {
                long t2;
                long t1 = System.nanoTime();
                sendOperation(stub);
                t2 = System.nanoTime();
                long latency = t2 - t1;

                if (id.equals("0") && measurementLeader)
                    System.out.println("M: " + latency);

                try {
                    if (rampup > 0) {
                        Thread.sleep(rampup);
                        rampup -= 100;
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            try {
                stub.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void interrupt() {
            try {
                stub.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            super.interrupt();
        }
    }

    private static Messages.ProxyMessage.Operation operationFromString(String str) {
        switch (str) {
            case "mapPut": return Messages.ProxyMessage.Operation.MAP_PUT;
            case "mapGet": return Messages.ProxyMessage.Operation.MAP_GET;
            case "attest": return Messages.ProxyMessage.Operation.MEMBERSHIP_JOIN;
            default: return null;
        }
    }
}
