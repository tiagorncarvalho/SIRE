package sire.proxy;

import sire.attestation.Quote;
import sire.messages.Messages;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.spec.ECPoint;
import java.util.Arrays;

public class ProxyWatz implements Runnable {
    private int proxyId;

    public ProxyWatz(int proxyId) {
        this.proxyId = proxyId;
    }

    @Override
    public void run() {
        try {
            ServerSocket ss = new ServerSocket(2500 + this.proxyId);
            Socket s;
            Object socketLock = new Object();
            while(true) {
                synchronized (socketLock) {
                    s = ss.accept();
                }
                System.out.println("New client!");
                new ProxyWatzThread(s).start();
                System.out.println("Connection accepted");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private class ProxyWatzThread extends Thread {
        private final Socket s;

        ProxyWatzThread (Socket s) {
            this.s = s;
            System.out.println("Proxy Thread started!");
        }

        @Override
        public void run() {
            try {
                DataOutputStream oos = new DataOutputStream(s.getOutputStream());
                DataInputStream ois = new DataInputStream(s.getInputStream());

                while (!s.isClosed()) {
                    //System.out.println("Running!");
                    byte[] b = ois.readAllBytes();
                    if(b != null) {
                        System.out.println("Message 0 received!");
                        int attPubKeyXSize = Byte.toUnsignedInt(b[32]);
                        byte[] attPubKeyX = Arrays.copyOfRange(b, 0, attPubKeyXSize);

                        int attPubKeyYSize = Byte.toUnsignedInt(b[68]);
                        byte[] attPubKeyY = Arrays.copyOfRange(b, 36, 36 + attPubKeyYSize);

                        ECPoint attesterPubKey = new ECPoint(new BigInteger(attPubKeyX), new BigInteger(attPubKeyY));
                        System.out.println("Key: " + attesterPubKey + " X: " + attesterPubKey.getAffineX() + " Y: "
                                + attesterPubKey.getAffineY());

                        Messages.ProtoMessage0 msg0 = Messages.ProtoMessage0.newBuilder()
                                .setAttesterId(attesterPubKey.hashCode())
                                .setAttesterPubSesKey(attesterPubKey)
                                .build();
                    }

                    b = ois.readAllBytes();
                    if(b != null) {
                        System.out.println("Message 2 received!");
                        System.out.println("ECDH Local Pub Key X:");
                        tempSize = Byte.toUnsignedInt(b[32]);
                        tempX = Arrays.copyOfRange(b, 0, tempSize);
                        System.out.println("Size: " + tempSize + " Key:" + Arrays.toString(tempX));

                        System.out.println("ECDH Local Pub Key Y:");
                        tempSize = Byte.toUnsignedInt(b[68]);
                        tempY = Arrays.copyOfRange(b, 36, 36 + tempSize);
                        System.out.println("Size: " + tempSize + " Key:" + Arrays.toString(tempY));

                        System.out.println("Quote:");
                        byte[] temp = Arrays.copyOfRange(b, 72, 72 + 200);
                        Quote q = new Quote(temp);
                        System.out.println(q);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}
