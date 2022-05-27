package sire.proxy;

import com.google.protobuf.ByteString;
import confidential.client.ConfidentialServiceProxy;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import sire.messages.Messages;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.SireException;
import vss.facade.SecretSharingException;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Objects;


public class ProxyWatz implements Runnable {
    private int proxyId;
    private ConfidentialServiceProxy serviceProxy;
    private Cipher symmetricCipher;
    private static final int AES_KEY_LENGTH = 128;
    private SecretKeyFactory secretKeyFactory;

    SchnorrSignatureScheme scheme;
    ECCurve curve;

    ECPoint ecdsaPubKey;
    BigInteger ecdsaPrivKey;

    public ProxyWatz(int proxyId) throws SireException {
        this.proxyId = proxyId;
        try {
            ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
            serviceProxy = new ConfidentialServiceProxy(proxyId, responseHandler);
            symmetricCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (SecretSharingException e) {
            throw new SireException("Failed to contact the distributed verifier", e);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
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
                        System.out.println("Reading message 0...");
                        readMessage0(b);
                        System.out.println("Message 0 received!");

                        System.out.println("Creating message 1...");
                        oos.write(Objects.requireNonNull(createMessage1()));
                        System.out.println("Message 1 sent!");

                        b = ois.readNBytes(288);
                        System.out.println("Reading message 2...");
                        byte[] data = readMessage2(b);
                        System.out.println("Message 2 received!");
                        System.out.println("Creating message 3...");
                        oos.write(createMessage3(data));
                        System.out.println("Message 3 sent!");
                        break;
                    }
                }
            } catch (IOException | SireException | SecretSharingException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }

        private void readMessage0(byte[] b) {
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

        }

        private byte[] createMessage1() {
            try {
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

        private byte[] readMessage2(byte[] b) throws SireException, SecretSharingException, IOException {
            byte[] mac = Arrays.copyOfRange(b, 272, 272 + 16);

            int localPubKeyXSize = Byte.toUnsignedInt(b[32]);
            byte[] localPubKeyX = Arrays.copyOfRange(b, 0, localPubKeyXSize);
            int localPubKeyYSize = Byte.toUnsignedInt(b[68]);
            byte[] localPubKeyY = Arrays.copyOfRange(b, 36, 36 + localPubKeyYSize);

            byte[] quote = Arrays.copyOfRange(b, 72, 272);

            byte[] tempMac = doMAC(macKey.toByteArray(), Arrays.copyOfRange(b, 0, localPubKeyXSize), Arrays.copyOfRange(b, 36, 36 + localPubKeyYSize), quote);

            System.out.println("Mac: " + bytesToHex(mac));
            System.out.println("TempMac: " + bytesToHex(tempMac));

            if(!Arrays.equals(mac, tempMac))
                throw new SireException("Invalid MAC for Message 2!");

            ECPoint tempKey = curve.createPoint(new BigInteger(bytesToHex(localPubKeyX), 16),
                    new BigInteger(bytesToHex(localPubKeyY), 16));
            if(!tempKey.equals(attesterPubKey))
                throw new SireException("Invalid attester public session key for Message 2!");

            byte[] anchor = Arrays.copyOfRange(quote, 0, 32);
            int watzVersion = quote[32];
            System.out.println("version: " + watzVersion);
            byte[] claimHash = Arrays.copyOfRange(quote, 36, 36 + 32);
            System.out.println("Claim hash: " + bytesToHex(claimHash));
            byte[] attestationKey = Arrays.copyOfRange(quote, 68, 68 + 65);
            System.out.println("Att key: " + bytesToHex(attestationKey));
            byte[] signature = Arrays.copyOfRange(quote, 133, 133 + 64);
            System.out.println("Sign: " + bytesToHex(signature));

            byte[] data;
            if((data = verifyQuote(anchor, watzVersion, claimHash, attestationKey, signature)) == null)
                throw new SireException("Invalid quote for Message 2!");

            return data;
        }

        private byte[] verifyQuote(byte[] anchor, int watzVersion, byte[] claimHash, byte[] attestationKey, byte[] signature)
                throws SireException, SecretSharingException {
            byte[] anc = scheme.computeHash(attesterPubKey.getXCoord().getEncoded(), attesterPubKey.getYCoord().getEncoded(),
                    ecdhPubKey.getXCoord().getEncoded(), ecdhPubKey.getYCoord().getEncoded());

            if(!Arrays.equals(anc, anchor))
                throw new SireException("Invalid anchor for Message 2!");

            Messages.ProtoEvidence evidence = Messages.ProtoEvidence.newBuilder()
                    .setWatzVersion(watzVersion)
                    .setServicePubKey(ByteString.copyFrom(attestationKey))
                    .setClaim(ByteString.copyFrom(claimHash))
                    .build();

            Messages.ProxyMessage req = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.ATTEST_VERIFY)
                    .setEvidence(evidence)
                    .setEcdsaSignature(ByteString.copyFrom(signature))
                    .build();

            //byte[] tmp = "A".repeat(2000).getBytes();
            byte[] tmp = serviceProxy.invokeOrdered(req.toByteArray()).getPainData();

            if (!Arrays.equals(tmp, new byte[]{0}))
                return tmp;

            return null;
        }


        private byte[] createMessage3(byte[] data) throws InvalidKeySpecException, SireException, IOException {
            byte[] tempData = encryptData(data);
            byte[] iv = symmetricCipher.getIV();
            byte[] encryptedData = Arrays.copyOfRange(tempData, 0, data.length);
            byte[] tag = Arrays.copyOfRange(tempData, data.length, tempData.length);

            System.out.println("Iv " + iv.length + " data " + data.length + " encyptedData " + encryptedData.length); //+ " tag " + tag.length);

            ByteArrayOutputStream output = new ByteArrayOutputStream();
            DataOutputStream baos = new DataOutputStream(output);

            baos.write(iv);
            baos.write(tag);
            baos.writeInt(encryptedData.length);
            baos.write(encryptedData);

            baos.flush();
            byte[] out = output.toByteArray();
            System.out.println("Length " + out.length);
            return out;
        }

        private byte[] encryptData(byte[] data) throws SireException {
            try {
                symmetricCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey.toByteArray(), "AES"));
                return symmetricCipher.doFinal(data);
            } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                throw new SireException("Failed to encrypt data", e);
            }
        }

        private byte[] doMAC(byte[] key, byte[]... blocks) {
            CMac cMac = new CMac(new AESEngine(), 128);
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
