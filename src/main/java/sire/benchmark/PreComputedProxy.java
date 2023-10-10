package sire.benchmark;


import confidential.client.ConfidentialServiceProxy;
import sire.messages.Messages;
import sire.proxy.ServersResponseHandlerWithoutCombine;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.SireException;
import vss.facade.SecretSharingException;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;

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




    public PreComputedProxy() {
    }

    public static void main(String[] args) throws InterruptedException, SecretSharingException, SireException {
        if (args.length != 5) {
            System.out.println("USAGE: benchmark.LatencyAttestationClient <initial client id> " +
                    "<num clients> <number of ops> <measurement leader?>");
            System.exit(-1);
        }
        initialId = Integer.parseInt(args[0]);
        int numClients = Integer.parseInt(args[1]);
        int numOperations = Integer.parseInt(args[2]);
        Messages.ProxyMessage.Operation operation = Messages.ProxyMessage.Operation.MAP_PUT;

        System.out.println("Operation: " + operation);

        boolean measurementLeader = Boolean.parseBoolean(args[3]);
        CountDownLatch latch = new CountDownLatch(numClients);

        Random random = new Random(1L);
        byte[] value = new byte[1024];
        random.nextBytes(value);

        new Thread(() -> {
            try {
                ServerSocket ss = new ServerSocket(2500);
                Socket s;
                while(true) {
                    s = ss.accept();
                    System.out.println("New client!");
                    new PreProxyThread(s).start();
                    System.out.println("Connection accepted");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();


        //stub.attest(appId, type, version, claim);

        ClientProcess[] clients = new ClientProcess[numClients];
        for (int i = 0; i < numClients; i++) {
            int sleepTime = random.nextInt(2000);
            Thread.sleep(sleepTime);

            int id = initialId + i;
            clients[i] = new ClientProcess(new ProcessBuilder("python3", "BenchmarkWorker.py",
                    String.valueOf(id), "1", String.valueOf(numOperations), String.valueOf(initialId),
                    String.valueOf(measurementLeader)).inheritIO(), id, numOperations,
                    operation, measurementLeader, latch);
            clients[i].start();
            Thread.sleep(10);
        }
        latch.await();
        System.out.println("Executing experiment");
    }

    private static class ClientProcess extends Thread {
        ProcessBuilder pb;
        int id;
        int numOperations;
        Messages.ProxyMessage.Operation operation;
        boolean measurementLeader;
        CountDownLatch latch;

        public ClientProcess(ProcessBuilder pb, int id, int numOperations, Messages.ProxyMessage.Operation operation,
                             boolean measurementLeader, CountDownLatch latch) throws SecretSharingException {
            this.id = id;
            this.numOperations = numOperations;
            this.operation = operation;
            this.measurementLeader = measurementLeader;
            ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
            serviceProxy = new ConfidentialServiceProxy(id, responseHandler);
            this.pb = pb;
            this.latch = latch;
        }

        @Override
        public void run() {
            latch.countDown();
            try {
                this.pb.start();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }


    private static class PreProxyThread extends Thread {

        private final Socket s;

        public PreProxyThread(Socket s) {
            this.s = s;
            System.out.println("Proxy Thread started!");
        }

        @Override
        public void run() {
            try {
                OutputStream os = s.getOutputStream();
                DataOutputStream dos = new DataOutputStream(os);
                InputStream is = s.getInputStream();

                while (!s.isClosed()) {
                    int size = ByteBuffer.wrap(is.readNBytes(4)).getInt();
                    byte[] bytes = is.readNBytes(size);
                    Messages.ProxyMessage msg = Messages.ProxyMessage.parseFrom(bytes);
                    System.out.println("M: " + ((long)msg.getLatency()));
                    synchronized (proxyLock) {
                        serviceProxy.invokeOrdered(msg.toByteArray());
                    }
                    byte[] bs = new byte[]{0};
                    dos.writeInt(bs.length);
                    dos.write(bs);
                    dos.flush();
                }
            } catch (SecretSharingException e) {
                e.printStackTrace();
            } catch (IOException ignored) {
            }
        }
    }
}

