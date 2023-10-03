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


import com.google.protobuf.ByteString;
import confidential.ConfidentialExtractedResponse;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.math.ec.ECPoint;
import sire.attestation.Evidence;
import sire.messages.Messages;
import sire.proxy.ServersResponseHandlerWithoutCombine;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.SireException;
import vss.facade.SecretSharingException;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;

import static sire.messages.ProtoUtils.*;

public class PreComputedProxy {
    private static ConfidentialServiceProxy serviceProxy;

    private static int initialId;
    private static final String appId = "app1";
    private static final String version = "1.0";
    private static final Object proxyLock = new Object();
    static SchnorrSignatureScheme scheme;

    private static Map<String, Integer> responseCounter;
    private static final Object counterLock = new Object();

    private static int numClientsPerHour;

    static {
        try {
            scheme = new SchnorrSignatureScheme();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static byte[] getMsg = Messages.ProxyMessage.newBuilder()
            .setOperation(Messages.ProxyMessage.Operation.MAP_GET)
            .setAppId("app1")
            .setKey("ldn9mm0tmiu89jo15s3tojer07keq91higztjvfoq5ic12fl6tkh5q17lyijgemtxud4gn59ca0bszjh9td1cankw9")
            .build().toByteArray();
    private static byte[] putMsg = Messages.ProxyMessage.newBuilder()
            .setOperation(Messages.ProxyMessage.Operation.MAP_PUT)
            .setAppId("app1")
            //.setKey("j7dw0sr5dhh9itj87spjb9dvkb358u5t6jn95j6wdfl1")
            //.setValue(ByteString.copyFrom("wwehfuq652ru0ibdr79eddqmwmhpmcjfz0hx3ihee3gu".getBytes()))
            .build().toByteArray();
    static BigInteger attesterPrivateKey = new BigInteger("4049546346519992604730332816858472394381393488413156548605745581385");
    static ECPoint attesterPubKey = scheme.getGenerator().multiply(attesterPrivateKey);
    static MessageDigest messageDigest;
    static ECPoint verifierPublicKey;

    static {
        try {
            messageDigest = MessageDigest.getInstance("SHA256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    static BigInteger randomPrivateKey = new BigInteger("2673E6E0D6F66A15DB4FA597B8160F23AB8767ED0E46692E01E04D49BD154426", 16);
    static ECPoint randomPublicKey = scheme.getGenerator().multiply(randomPrivateKey);

    static SchnorrSignature signature = scheme.computeSignature(computeHash(attesterPubKey.getEncoded(true)), attesterPrivateKey,
            attesterPubKey, randomPrivateKey, randomPublicKey);

    private static byte[] msg0;


    private static byte[] computeHash(byte[]... contents) {
        for (byte[] content : contents) {
            messageDigest.update(content);
        }
        return messageDigest.digest();
    }


    public PreComputedProxy() throws NoSuchAlgorithmException {
    }

    public static void main(String[] args) throws InterruptedException, SecretSharingException, SireException, IOException {
        if (args.length != 6) {
            System.out.println("USAGE: benchmark.LatencyAttestationClient <initial client id> " +
                    "<num clients> <number of ops> <operation> <clients per hour> <measurement leader?>");
            System.exit(-1);
        }
        initialId = Integer.parseInt(args[0]);
        int numClients = Integer.parseInt(args[1]);
        System.out.println(numClients);
        int numOperations = Integer.parseInt(args[2]);
        Messages.ProxyMessage.Operation operation;
        if((operation = operationFromString(args[3])) == null) {
            System.out.println("Couldn't parse operation. Available operations:\n - attest\n - getKey");
            System.exit(-1);
        }
        numClientsPerHour = Integer.parseInt(args[4]);

        System.out.println("Operation: " + operation);

        boolean measurementLeader = Boolean.parseBoolean(args[5]);
        CountDownLatch latch = new CountDownLatch(numClients);

        Random random = new Random(1L);
        byte[] value = new byte[1024];
        random.nextBytes(value);

        //stub.attest(appId, type, version, claim);
        responseCounter = new HashMap<>();

        Client[] clients = new Client[numClients];
        for (int i = 0; i < numClients; i++) {
            System.out.println("Client " + i);
            int sleepTime = random.nextInt(2000);
            Thread.sleep(sleepTime);

            int id = initialId + i;
            clients[i] = new Client(id, numOperations, operation, measurementLeader, latch);
            clients[i].start();
            Thread.sleep(10);
        }
        latch.await();
        System.out.println("Executing experiment");
    }

    private static class Client extends Thread {
        private final int id;
        private final int numOperations;
        private int rampup = 1000;
        ConfidentialServiceProxy serviceProxy;
        Messages.ProxyMessage.Operation operation;
        private final boolean measurementLeader;
        private final CountDownLatch latch;
        private ServerSocket serverSocket;


        Client(int id, int numOperations, Messages.ProxyMessage.Operation operation, boolean measurementLeader, CountDownLatch latch) throws SecretSharingException, SireException, IOException {
            this.id = id;
            this.numOperations = numOperations;
            this.operation = operation;
            this.measurementLeader = measurementLeader;
            this.latch = latch;
            ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
            serverSocket = new ServerSocket(5151 + id);
            new Thread(() -> {
                Socket s;
                for (int i = 0; i < 4; i++) {
                    try {
                        s = serverSocket.accept();
                        new ReceivingProxyThread(s).start();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();

            msg0 = Messages.ProxyMessage.newBuilder()
                    .setDeviceId("" + id)
                    .setPubKey(ByteString.copyFrom(attesterPubKey.getEncoded(true)))
                    .setSignature(schnorrToProto(signature))
                    .setOperation(Messages.ProxyMessage.Operation.ATTEST_TIMESTAMP)
                    .build().toByteArray();

            serviceProxy = new ConfidentialServiceProxy(id, responseHandler);

            if(measurementLeader) {
                Response response;
                try {
                    Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                            .setOperation(Messages.ProxyMessage.Operation.ATTEST_GET_PUBLIC_KEY)
                            .build();
                    byte[] b = msg.toByteArray();
                    response = serviceProxy.invokeOrdered(b);//new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
                } catch (SecretSharingException e) {
                    throw new SireException("Failed to obtain verifier's public key", e);
                }
                verifierPublicKey = scheme.decodePublicKey(response.getPainData());
            }
        }

        long sendOperation() {
            try {
                switch (operation) {
                    case MEMBERSHIP_JOIN: attest();
                    case MAP_PUT: return accessIntersection(new Random().nextInt(9) - 1);
                    case MAP_GET: get();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return 0;
        }

        @Override
        public void run() {
            latch.countDown();
            for (int i = 1; i < numOperations; i++) {
                long t2;
                long t1 = System.nanoTime();
                long waitTime = sendOperation();
                t2 = System.nanoTime();
                long latency = t2 - t1 - waitTime;
                if (id == initialId && measurementLeader)
                    System.out.println("M: " + latency);

                try {
                    if (rampup > 0) {
                        Thread.sleep(rampup);
                        rampup -= 100;
                    }
                    else
                        Thread.sleep((numClientsPerHour/3600) * 1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
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

        public long accessIntersection(int lane) throws InterruptedException, SecretSharingException {
            System.out.println("Requesting!");
            Messages.ProxyMessage.Builder builder = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_PUT)
                    .setDeviceId(this.id + "")
                    .setAppId(appId)
                    .setKey("lane" + lane);
            Messages.ProxyMessage request = builder.setValue(ByteString.copyFrom(new byte[]{1})).build();
            Messages.ProxyMessage release = builder.setValue(ByteString.copyFrom(new byte[]{0})).build();
            Response res = serviceProxy.invokeOrdered(request.toByteArray());

            byte b = res.getPainData()[0];
            long waitTime = 3000000000L;
            if(b == 0) {
                long startTime = System.nanoTime();
                System.out.println("Idle... " + this.id);
                synchronized (counterLock) {
                    responseCounter.put(this.id + "", 0);
                }
                try {
                    while(responseCounter.get(this.id + "") < 4) {
                        Thread.sleep(100);
                    }
                } catch (NullPointerException e) {
                    e.printStackTrace();
                }
                synchronized (counterLock) {
                    responseCounter.remove(this.id + "");
                }
                waitTime = System.nanoTime() - startTime + 5000000000L;
                System.out.println("Crossing...");
                Thread.sleep(5000);
            } else {
                System.out.println("Crossing...");
                Thread.sleep(3000);
            }
            System.out.println("Releasing!");
            serviceProxy.invokeOrdered(release.toByteArray());
            return waitTime;
        }

        private void attest() throws SecretSharingException {
            ConfidentialExtractedResponse res = serviceProxy.invokeOrdered2(msg0);
            byte[] data = Arrays.copyOfRange(res.getPlainData(), res.getPlainData().length - 124, res.getPlainData().length);
            byte[] ts = Arrays.copyOfRange(data, 0, 91);

            Evidence evidence = new Evidence("1.0", "measure1".getBytes(), attesterPubKey.getEncoded(true));

            byte[] signingHash = computeHash(
                    attesterPubKey.getEncoded(true),
                    "1.0".getBytes(),
                    "measure1".getBytes(),
                    ts,
                    appId.getBytes()
            );

            signature = scheme.computeSignature(signingHash, attesterPrivateKey,
                    attesterPubKey, randomPrivateKey, randomPublicKey);

            Messages.ProxyMessage attReq = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MEMBERSHIP_JOIN)
                    .setAppId("app1")
                    .setDeviceId("" + id)
                    .setTimestamp(ByteString.copyFrom(ts))
                    .setEvidence(evidenceToProto(evidence))
                    .setPubKey(ByteString.copyFrom(attesterPubKey.getEncoded(true)))
                    .setSignature(schnorrToProto(signature))
                    .build();
            serviceProxy.invokeOrdered2(attReq.toByteArray());
        }
    }

    private static class ReceivingProxyThread extends Thread {
        Socket s;

        public ReceivingProxyThread(Socket s) {
            this.s = s;
        }

        @Override
        public void run() {
            try {
                ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

                while (!s.isClosed()) {
                    Object o;
                    while ((o = ois.readObject()) != null) {
                        if(o instanceof Messages.ProxyResponse) {
                            Messages.ProxyResponse res = (Messages.ProxyResponse) o;
                            String deviceId = res.getDeviceId();
                            synchronized (counterLock) {
                                if(responseCounter.containsKey(deviceId))
                                    responseCounter.put(deviceId, responseCounter.get(deviceId) + 1);
                                else
                                    responseCounter.put(deviceId, 1);
                            }
                        }
                    }
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    private static Messages.ProxyMessage.Operation operationFromString(String str) {
        switch (str) {
            case "mapPut":
            case "intersection" :
                return Messages.ProxyMessage.Operation.MAP_PUT;
            case "mapGet": return Messages.ProxyMessage.Operation.MAP_GET;
            case "attest": return Messages.ProxyMessage.Operation.MEMBERSHIP_JOIN;
            default: return null;
        }
    }
}
