package sire.proxy;

import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import sire.schnorr.SchnorrSignatureScheme;

import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECParameterSpec;
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
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private class ProxyWatzThread extends Thread {
        private final Socket s;
        SchnorrSignatureScheme scheme;
        ECCurve curve;

        ECPoint ecdsaPubKey;
        BigInteger ecdsaPrivKey;
        ECPoint verSessionPubKey;
        BigInteger verSessionPrivateKey;

        ProxyWatzThread (Socket s) throws NoSuchAlgorithmException {
            this.s = s;
            System.out.println("Proxy Thread started!");
            this.scheme = new SchnorrSignatureScheme();
            this.curve = scheme.getCurve();
            this.ecdsaPubKey = curve.createPoint(new BigInteger("a22ac2720edd386d52c1944260bbcbf7595109bc252bbe35c7ffc8ade211604e", 16),
                    new BigInteger("5c4f6db0631a27aedb0e0d16ffb21cdb69096a948c9081890347f17edb82f50b", 16));
            this.verSessionPubKey = curve.createPoint(new BigInteger("d4f1ab37f973051ec59f9400761b250360659a18ca1a4cea2c7f783b68c04c51", 16),
                    new BigInteger("e01ad742889934ef1ba29cce3d1a8222d374a607fd042b80066ebc711c19a639", 16));
            this.verSessionPrivateKey = new BigInteger("450915b28c8e070e900146e5d809f5027b763253f971503569e9a3ff4f276f9e", 16);
            this.ecdsaPrivKey = new BigInteger("0f27fdab57a84711ceb90361bdb45ce26d4eb6cae5245a2e09f696ec16a9bc6c", 16);
        }

        @Override
        public void run() {
            try {
                DataOutputStream oos = new DataOutputStream(s.getOutputStream());
                DataInputStream ois = new DataInputStream(s.getInputStream());

                while (!s.isClosed()) {
                    System.out.println("Running!");
                    byte[] b = ois.readAllBytes();
                    if(b != null) {
                        System.out.println("Message 0 received!");

                        int attPubKeyXSize = Byte.toUnsignedInt(b[32]);
                        String attPubKeyX = bytesToHex(Arrays.copyOfRange(b, 0, attPubKeyXSize));

                        int attPubKeyYSize = Byte.toUnsignedInt(b[68]);
                        String attPubKeyY = bytesToHex(Arrays.copyOfRange(b, 36, 36 + attPubKeyYSize));

                        ECPoint attesterPubKey = curve.createPoint(new BigInteger(attPubKeyX, 16), new BigInteger(attPubKeyY, 16));
                        System.out.println("X: " + attesterPubKey.getAffineXCoord() + " Y: " + attesterPubKey.getAffineYCoord());

                        ECPoint sharedKey = attesterPubKey.multiply(verSessionPrivateKey);
                        sharedKey = sharedKey.normalize();


                        CMac cmac = new CMac(new AESEngine());

                        byte[] gabx = sharedKey.getXCoord().getEncoded();
                        System.out.println("Big endian: " + Arrays.toString(gabx));

                        byte[] revgabx = gabx.clone();
                        int i = 0;
                        int j = revgabx.length - 1;
                        byte tmp;
                        while (j > i) {
                            tmp = revgabx[j];
                            revgabx[j] = revgabx[i];
                            revgabx[i] = tmp;
                            j--;
                            i++;
                        }

                        System.out.println("Little endian: " + Arrays.toString(revgabx));
                        cmac.init(new KeyParameter(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
                        cmac.update(revgabx, 0, revgabx.length);
                        byte[] out = new byte[cmac.getMacSize()];
                        cmac.doFinal(out, 0);

                        System.out.println("KDK: " + bytesToHex(out));

                        CMac cmacKey = new CMac(new AESEngine());
                        cmacKey.init(new KeyParameter(out));
                        String sequence = "01534d4b008000";
                        byte[] msg = hexStringToByteArray(sequence);
                        cmacKey.update(msg, 0, msg.length);
                        byte[] macKey = new byte[cmacKey.getMacSize()];
                        cmacKey.doFinal(macKey, 0);

                        byte[] pubKeyX = verSessionPubKey.getXCoord().getEncoded();
                        int pubKeyXSize = pubKeyX.length;
                        byte[] pubKeyY = verSessionPubKey.getYCoord().getEncoded();
                        int pubKeyYSize = pubKeyY.length;

                        byte[] ecdsaPubKeyX = ecdsaPubKey.getXCoord().getEncoded();
                        int ecdsaPubKeyXSize = ecdsaPubKeyX.length;
                        byte[] ecdsaPubKeyY = ecdsaPubKey.getYCoord().getEncoded();
                        int ecdsaPubKeyYSize = ecdsaPubKeyY.length;


                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        baos.write(pubKeyX);
                        baos.write(attesterPubKey.getXCoord().getEncoded());
                        byte[] signingData = baos.toByteArray();
                        //simulator uses ecdsa, sire uses schnorr

                        baos.reset();
                        baos.write(pubKeyX);
                        baos.write(pubKeyXSize);
                        baos.write(pubKeyY);
                        baos.write(pubKeyYSize);
                        baos.write(ecdsaPubKeyX);
                        baos.write(ecdsaPubKeyXSize);
                        baos.write(ecdsaPubKeyY);
                        baos.write(ecdsaPubKeyYSize);
                        baos.write(signingData);
                        byte[] content = baos.toByteArray();

                        CMac fMac = new CMac(new AESEngine());
                        fMac.init(new KeyParameter(macKey));
                        fMac.update(content, 0, content.length);
                        byte[] resMac = new byte[fMac.getMacSize()];
                        fMac.doFinal(resMac, 0);

                        baos.reset();
                        baos.write(content);
                        baos.write(resMac);
                        byte[] msg1 = baos.toByteArray();

                        oos.write(msg1);
                    }

                    /*b = ois.readAllBytes();
                    if(b != null) {
                        System.out.println("Message 2 received!");
                        //read message 2

                        //prepare message 3

                        //send message 3

                    }*/
                    break;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
        public static String bytesToHex(byte[] bytes) {
            byte[] hexChars = new byte[bytes.length * 2];
            for (int j = 0; j < bytes.length; j++) {
                int v = bytes[j] & 0xFF;
                hexChars[j * 2] = HEX_ARRAY[v >>> 4];
                hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
            }
            return new String(hexChars, StandardCharsets.UTF_8);
        }

        public static byte[] hexStringToByteArray(String s) {
            int len = s.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i+1), 16));
            }
            return data;
        }
    }
}
