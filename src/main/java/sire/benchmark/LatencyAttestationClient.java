package sire.benchmark;

import sire.device.DeviceStub;
import sire.messages.Messages;
import sire.serverProxyUtils.DeviceContext;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class LatencyAttestationClient {
    //TODO Needs to be reimplemented... From the ground up.

    private static String initialId;
    private static final String appId = "app1";
    private static final String waTZVersion = "1.0";

    public static void main(String[] args) throws InterruptedException, NoSuchPaddingException, NoSuchAlgorithmException, ClassNotFoundException {
        if (args.length != 5) {
            System.out.println("USAGE: benchmark.LatencyAttestationClient <initial client id> " +
                    "<num clients> <number of ops> <operation> <measurement leader?>");
            System.exit(-1);
        }
        initialId = args[0];
        DeviceContext.DeviceType type = DeviceContext.DeviceType.CAMERA;
        byte[] claim = "measure1".getBytes();
        int numClients = Integer.parseInt(args[1]);
        int numOperations = Integer.parseInt(args[2]);
        Messages.ProxyMessage.Operation operation;
        if((operation = operationFromString(args[3])) == null) {
            System.out.println("Couldn't parse operation. Available operations:\n - attest\n - getKey");
            System.exit(-1);
        }

        System.out.println("Operation: " + operation);

        boolean measurementLeader = Boolean.parseBoolean(args[4]);

        Random random = new Random(1L);
        byte[] value = new byte[1024];
        random.nextBytes(value);

        DeviceStub stub = new DeviceStub();

        Client[] clients = new Client[numClients];
        for (int i = 0; i < numClients; i++) {
            int sleepTime = random.nextInt(2000);
            Thread.sleep(sleepTime);

            if (i > 0) {
                stub = new DeviceStub();
            }

            String id = Integer.toString(Integer.parseInt(initialId) + i);
            clients[i] = new Client(Integer.toString(Integer.parseInt(initialId) + i), stub, numOperations, measurementLeader) {
                @Override
                void sendOperation(DeviceStub stub) {
                    System.out.println("Sending op!");
                    try {
                        switch (operation) {
                            case ATTEST_VERIFY -> stub.attest(appId, id, type, waTZVersion, claim);
                            case MAP_PUT -> stub.put(id, appId, id, value);
                            case MAP_GET -> stub.getData(id, appId, "key");
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
            if (id.equals(initialId)) {
                if (measurementLeader)
                    System.out.println("I'm measurement leader");
                System.out.println("Sending test data...");
            }
            sendOperation(stub);
            if (id.equals(initialId)) {
                System.out.println("Executing experiment for " + numOperations + " ops");
            }
            for (int i = 1; i < numOperations; i++) {
                long t2;
                long t1 = System.nanoTime();
                sendOperation(stub);
                t2 = System.nanoTime();
                long latency = t2 - t1;

                if (id.equals(initialId) && measurementLeader)
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
        return switch (str) {
            case "mapPut" -> Messages.ProxyMessage.Operation.MAP_PUT;
            case "mapGet" -> Messages.ProxyMessage.Operation.MAP_GET;
            case "attest" -> Messages.ProxyMessage.Operation.ATTEST_VERIFY;
            default -> null;
        };
    }
}
