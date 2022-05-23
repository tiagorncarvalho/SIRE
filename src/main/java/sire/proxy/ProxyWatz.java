package sire.proxy;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import sire.schnorr.SchnorrSignatureScheme;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;


public class ProxyWatz implements Runnable {
    private int proxyId;

    SchnorrSignatureScheme scheme;
    ECCurve curve;

    ECPoint ecdsaPubKey;
    BigInteger ecdsaPrivKey;

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
        private final ECPoint ecdhPubKey;
        private final BigInteger ecdhPrivateKey;
        private BigInteger macKey;
        private BigInteger sessionKey;
        private ECPoint attesterPubKey;
        private ECPoint sharedSecret;

        ProxyWatzThread (Socket s) throws NoSuchAlgorithmException {
            this.s = s;
            System.out.println("Proxy Thread started!");
            scheme = new SchnorrSignatureScheme();
            curve = scheme.getCurve();
            ecdsaPubKey = curve.createPoint(new BigInteger("f670099bf7178ec7398ac883d67c1bd5ccf53280b72316d14b41f2cf9566a52a", 16),
                    new BigInteger("2dda697b5fa54b89d607904da468874a4be4e96f6efe8b05eba71c85266047d2", 16));
            ecdsaPrivKey = new BigInteger("d9c6df5618bcf8b550d6cc02ad69f22c7166833140c00954345de3e812d6c378", 16);

            ecdhPubKey = curve.createPoint(new BigInteger("971907e89c9c2f3870bedbc8e4eb492b68ba0f3bbd66a712b29098d5f9d55ce6", 16),
                    new BigInteger("0310fb91babcd11c629a672bf7a6b6c56d828220eb9a06067339cb501f5ee3ee", 16));
            ecdhPrivateKey = new BigInteger("964a3a0393ddf3f04ead3c4be85e5fbe5f3a2323eb36cbfb41c1dd0ed8394bfa", 16);
        }

        @Override
        public void run() {
            try {
                DataOutputStream oos = new DataOutputStream(s.getOutputStream());
                DataInputStream ois = new DataInputStream(s.getInputStream());
                while (!s.isClosed()) {
                    System.out.println("Running!");
                    byte[] b = ois.readNBytes(72);
                    if(b != null) {
                        System.out.println("Message 0 received!");

                        oos.write(Objects.requireNonNull(processMessage0(b)));
                        System.out.println("Message 1 sent!");
                        break;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private byte[] processMessage0(byte[] b) {
            try {
                int attPubKeyXSize = Byte.toUnsignedInt(b[32]);
                String attPubKeyX = bytesToHex(Arrays.copyOfRange(b, 0, attPubKeyXSize));

                int attPubKeyYSize = Byte.toUnsignedInt(b[68]);
                String attPubKeyY = bytesToHex(Arrays.copyOfRange(b, 36, 36 + attPubKeyYSize));

                attesterPubKey = curve.createPoint(new BigInteger(attPubKeyX, 16), new BigInteger(attPubKeyY, 16));

                sharedSecret = attesterPubKey.multiply(ecdhPrivateKey);
                sharedSecret = sharedSecret.normalize();

                CMac cmac = new CMac(new AESEngine());

                byte[] gabx = sharedSecret.getXCoord().getEncoded();

                cmac.init(new KeyParameter(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
                cmac.update(gabx, 0, gabx.length);
                byte[] out = new byte[cmac.getMacSize()];
                cmac.doFinal(out, 0);

                macKey = new BigInteger(doMAC(out, hexStringToByteArray("01534d4b008000")));

                sessionKey = new BigInteger(doMAC(out, hexStringToByteArray("01534b008000")));

                byte[] ecdhPubKeyX = ecdhPubKey.getXCoord().getEncoded();
                int ecdhPubKeyXSize = ecdhPubKeyX.length;
                byte[] ecdhPubKeyY = ecdhPubKey.getYCoord().getEncoded();
                int ecdhPubKeyYSize = ecdhPubKeyY.length;

                byte[] ecdsaPubKeyX = ecdsaPubKey.getXCoord().getEncoded();
                int ecdsaPubKeyXSize = ecdsaPubKeyX.length;
                byte[] ecdsaPubKeyY = ecdsaPubKey.getYCoord().getEncoded();
                int ecdsaPubKeyYSize = ecdsaPubKeyY.length;

                ByteArrayOutputStream output = new ByteArrayOutputStream();
                DataOutputStream baos = new DataOutputStream(output);

                baos.write(ecdhPubKeyX);
                baos.write(ecdhPubKeyY);
                baos.write(attesterPubKey.getXCoord().getEncoded());
                baos.write(attesterPubKey.getYCoord().getEncoded());
                baos.flush();
                byte[] signingData = output.toByteArray();

                byte[] signature = scheme.signECDSA(ecdsaPrivKey, signingData); //simulator uses ecdsa, sire uses schnorr

                output.reset();
                baos.write(ecdhPubKeyX);
                baos.write(ecdhPubKeyY);
                baos.write(ecdsaPubKeyX);
                baos.write(ecdsaPubKeyY);
                baos.flush();
                byte[] keys = output.toByteArray();

                byte[] resMac = doMAC(macKey.toByteArray(), keys, signature);

                output.reset();
                baos.write(ecdhPubKeyX);
                baos.writeInt(ecdhPubKeyXSize);
                baos.write(ecdhPubKeyY);
                baos.writeInt(ecdhPubKeyYSize);
                baos.write(ecdsaPubKeyX);
                baos.writeInt(ecdsaPubKeyXSize);
                baos.write(ecdsaPubKeyY);
                baos.writeInt(ecdsaPubKeyYSize);
                baos.write(signature);
                baos.flush();
                byte[] content = output.toByteArray();


                output.reset();
                baos.write(content);
                baos.write(resMac);
                baos.flush();
                return output.toByteArray(); //msg1
            } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
            return null;
        }

        private byte[] doMAC(byte[] key, byte[]... blocks) {
            CMac cMac = new CMac(new AESEngine());
            cMac.init(new KeyParameter(key));
            for(byte[] b : blocks)
                cMac.update(b, 0, b.length);
            byte[] result = new byte[cMac.getMacSize()];
            cMac.doFinal(result, 0);

            return result;
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
