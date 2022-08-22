package sire.benchmark;


import com.google.protobuf.ByteString;
import confidential.client.ConfidentialServiceProxy;
import sire.device.DeviceStub;
import sire.membership.DeviceContext;
import sire.messages.Messages;
import sire.proxy.ServersResponseHandlerWithoutCombine;
import vss.facade.SecretSharingException;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class PreComputedProxy {
    private static ConfidentialServiceProxy serviceProxy;

    private static int initialId;
    private static final String appId = "app1";
    private static final String version = "1.0";
    private static final Object proxyLock = new Object();
    private static byte[] getMsg = Messages.ProxyMessage.newBuilder()
            .setOperation(Messages.ProxyMessage.Operation.MAP_GET)
            .setAppId("app1")
            .setKey("ldn9mm0tmiu89jo15s3tojer07keq91higztjvfoq5ic12fl6tkh5q17lyijgemtxud4gn59ca0bszjh9td1cankw9")
            .build().toByteArray();
    private static byte[] putMsg = Messages.ProxyMessage.newBuilder()
            .setOperation(Messages.ProxyMessage.Operation.MAP_PUT)
            .setAppId("app1")
            .setKey("j7dw0sr5dhh9itj87spjb9dvkb358u5t6jn95j6wdfl1")
            .setValue(ByteString.copyFrom("wwehfuq652ru0ibdr79eddqmwmhpmcjfz0hx3ihee3gu".getBytes()))
            .build().toByteArray();

    public static void main(String[] args) throws InterruptedException, SecretSharingException {
        if (args.length != 5) {
            System.out.println("USAGE: benchmark.LatencyAttestationClient <initial client id> " +
                    "<num clients> <number of ops> <operation> <measurement leader?>");
            System.exit(-1);
        }
        initialId = Integer.parseInt(args[0]);
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

        //stub.attest(appId, type, version, claim);

        Client[] clients = new Client[numClients];
        for (int i = 0; i < numClients; i++) {
            int sleepTime = random.nextInt(2000);
            Thread.sleep(sleepTime);

            int id = initialId + i;
            clients[i] = new Client(id, numOperations, operation, measurementLeader);
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

    private static class Client extends Thread {
        private final int id;
        private final int numOperations;
        private int rampup = 1000;
        ConfidentialServiceProxy serviceProxy;
        Messages.ProxyMessage.Operation operation;
        private final boolean measurementLeader;


        Client(int id, int numOperations, Messages.ProxyMessage.Operation operation, boolean measurementLeader) throws SecretSharingException {
            this.id = id;
            this.numOperations = numOperations;
            this.operation = operation;
            this.measurementLeader = measurementLeader;
            ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();

            serviceProxy = new ConfidentialServiceProxy(id, responseHandler);
        }

        void sendOperation() {
            try {
                switch (operation) {
                    case MEMBERSHIP_JOIN -> attest();
                    case MAP_PUT -> put();
                    case MAP_GET -> get();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            if (id == initialId) {
                if (measurementLeader)
                    System.out.println("I'm measurement leader");
                System.out.println("Sending test data...");
            }
            sendOperation();
            if (id == initialId) {
                System.out.println("Executing experiment for " + numOperations + " ops");
            }
            long latencyAvg = 0;
            long latencyMin = Long.MAX_VALUE;
            long latencyMax = 0;
            for (int i = 1; i < numOperations; i++) {
                long t2;
                long t1 = System.nanoTime();
                sendOperation();
                t2 = System.nanoTime();
                long latency = t2 - t1;
                if(latency < latencyMin)
                    latencyMin = latency;
                if(latency > latencyMax)
                    latencyMax = latency;
                latencyAvg += latency;
                if (id == initialId && measurementLeader)
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

            if (id == initialId && measurementLeader) {
                //LongSummaryStatistics statistics = Arrays.stream(latencies).summaryStatistics();
                double average = (latencyAvg / (float) numOperations) / 1_000_000.0;
                long max = latencyMax / 1_000_000;
                long min = latencyMin / 1_000_000;

                //double std = calculateStandardDeviation(latencies, average);
                System.out.println("=============================");
                System.out.printf("Avg: %.3f ms\n", average);
                //System.out.printf("Std: %.3f ms\n", std);
                System.out.printf("Min: %d ms\n", min);
                System.out.printf("Max: %d ms\n", max);
                System.out.println("=============================");
            }

            serviceProxy.close();
        }

        private double calculateStandardDeviation(long[] data, double avg) {
            double std = 0.0;
            for(long l : data)
                std += Math.pow((l / 1_000_000.0) - avg, 2);
            return Math.sqrt(std / data.length);
        }



        @Override
        public void interrupt() {
            serviceProxy.close();
            super.interrupt();
        }

        private void get() throws SecretSharingException {
            serviceProxy.invokeUnordered(getMsg);
        }

        private void put() throws SecretSharingException {
            serviceProxy.invokeOrdered(putMsg);
        }

        private static void attest() {

        }
    }

    private static Messages.ProxyMessage.Operation operationFromString(String str) {
        return switch (str) {
            case "mapPut" -> Messages.ProxyMessage.Operation.MAP_PUT;
            case "mapGet" -> Messages.ProxyMessage.Operation.MAP_GET;
            case "attest" -> Messages.ProxyMessage.Operation.MEMBERSHIP_JOIN;
            default -> null;
        };
    }
}

