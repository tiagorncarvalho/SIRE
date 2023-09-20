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
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.math.ec.ECPoint;
import sire.attestation.Evidence;
import sire.messages.Messages;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.SireException;
import vss.facade.SecretSharingException;
import java.math.BigInteger;
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
            .setKey("j7dw0sr5dhh9itj87spjb9dvkb358u5t6jn95j6wdfl1")
            .setValue(ByteString.copyFrom("wwehfuq652ru0ibdr79eddqmwmhpmcjfz0hx3ihee3gu".getBytes()))
            .build().toByteArray();
    static BigInteger attesterPrivateKey = new BigInteger("4049546346519992604730332816858472394381393488413156548605745581385");
    static ECPoint attesterPubKey = scheme.getGenerator().multiply(attesterPrivateKey);
    static ECPoint verifierPublicKey;

    static BigInteger randomPrivateKey = new BigInteger("2673E6E0D6F66A15DB4FA597B8160F23AB8767ED0E46692E01E04D49BD154426", 16);
    static ECPoint randomPublicKey = scheme.getGenerator().multiply(randomPrivateKey);

    static SchnorrSignature signature = scheme.computeSignature(computeHash(attesterPubKey.getEncoded(true)), attesterPrivateKey,
            attesterPubKey, randomPrivateKey, randomPublicKey);

    private static byte[] msg0;


    private static byte[] computeHash(byte[]... contents) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            for (byte[] content : contents) {
                messageDigest.update(content);
            }
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }


    public PreComputedProxy() throws NoSuchAlgorithmException {
    }

    public static void main(String[] args) throws InterruptedException, SecretSharingException, SireException {
        if (args.length != 5) {
            System.out.println("USAGE: benchmark.LatencyAttestationClient <initial client id> " +
                    "<num clients> <number of ops> <operation> <measurement leader?>");
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

        System.out.println("Operation: " + operation);

        boolean measurementLeader = Boolean.parseBoolean(args[4]);
        CountDownLatch latch = new CountDownLatch(numClients);

        Random random = new Random(1L);
        byte[] value = new byte[1024];
        random.nextBytes(value);

        //stub.attest(appId, type, version, claim);

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


        Client(int id, int numOperations, Messages.ProxyMessage.Operation operation, boolean measurementLeader, CountDownLatch latch) throws SecretSharingException, SireException {
            this.id = id;
            this.numOperations = numOperations;
            this.operation = operation;
            this.measurementLeader = measurementLeader;
            this.latch = latch;

            msg0 = Messages.ProxyMessage.newBuilder()
                    .setDeviceId("" + id)
                    .setPubKey(ByteString.copyFrom(attesterPubKey.getEncoded(true)))
                    .setSignature(schnorrToProto(signature))
                    .setOperation(Messages.ProxyMessage.Operation.ATTEST_TIMESTAMP)
                    .build().toByteArray();

            serviceProxy = new ConfidentialServiceProxy(id);

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

        void sendOperation() {
            try {
                switch (operation) {
                    case MEMBERSHIP_JOIN: attest();
                    case MAP_PUT: put();
                    case MAP_GET: get();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            latch.countDown();
            System.out.println(latch.getCount());
            for (int i = 1; i < numOperations; i++) {
                long t2;
                long t1 = System.nanoTime();
                sendOperation();
                t2 = System.nanoTime();
                long latency = t2 - t1;
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

        private void attest() throws SecretSharingException {
            Response res = serviceProxy.invokeOrdered(msg0);
            byte[] data = Arrays.copyOfRange(res.getPainData(), res.getPainData().length - 124, res.getPainData().length);
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
            serviceProxy.invokeOrdered(attReq.toByteArray());
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

