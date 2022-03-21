package sire.dummy;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import sire.protos.Messages.*;
import sire.messages.Message1;
import sire.messages.Message3;
import static sire.utils.ProtoUtils.*;
import com.google.protobuf.ByteString;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.DeviceContext;
import sire.serverProxyUtils.SireException;
import sire.utils.Evidence;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

//TODO Add DeviceType Support
public class AttesterStub {
    String attesterId;
    int proxyId;
    String appId;
    String waTZVersion;
    int port;
    Socket s;
    ObjectOutputStream oos;
    ObjectInputStream ois;
    private final BigInteger order;
    private final ECCurve curve;
    private static final int AES_KEY_LENGTH = 128;
    private static final SecureRandom rndGenerator = new SecureRandom("sire".getBytes());
    private static CMac macEngine;
    private static SecretKeyFactory secretKeyFactory;
    private static MessageDigest messageDigest;
    private static Cipher symmetricCipher;

    public AttesterStub(String attesterId, int proxyId, String appId, String waTZVersion) throws NoSuchAlgorithmException,
            NoSuchPaddingException, IOException, ClassNotFoundException {
        this.attesterId = attesterId;
        this.proxyId = proxyId;
        this.appId = appId;
        this.waTZVersion = waTZVersion;
        this.port = 2500 + proxyId;
        byte[] claim = "claim".getBytes();
        secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        messageDigest = MessageDigest.getInstance("SHA256");
        macEngine = new CMac(new AESEngine());
        symmetricCipher = Cipher.getInstance("AES/GCM/NoPadding");
        SchnorrSignatureScheme signatureScheme = new SchnorrSignatureScheme();
        BigInteger prime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
        BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);

        BigInteger cofactor = prime.divide(order);
        curve = new ECCurve.Fp(prime, a, b, order, cofactor);
        try {
            this.s = new Socket("localhost", port);
            this.oos = new ObjectOutputStream(s.getOutputStream());
            this.ois = new ObjectInputStream(s.getInputStream());

            ECPoint verifierPublicKey = getVerifierPublicKey();
            ECPoint curveGenerator = signatureScheme.getGenerator();
            BigInteger attesterPrivateKey = new BigInteger("4049546346519992604730332816858472394381393488413156548605745581385");
            ECPoint attesterPublicKey = curveGenerator.multiply(attesterPrivateKey);

            BigInteger attesterSessionPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
            ECPoint attesterSessionPublicKey = curveGenerator.multiply(attesterSessionPrivateKey);

            //Message0 message0 = new Message0(attesterId, attesterSessionPublicKey.getEncoded(true));

            Message1 message1 = join(appId, attesterId, attesterSessionPublicKey.getEncoded(true));

            byte[] sessionPublicKeysHash = computeHash(message1.getVerifierPublicSessionKey(),
                    attesterSessionPublicKey.getEncoded(true));

            //computing shared keys
            ECPoint verifierSessionPublicKey = signatureScheme.decodePublicKey(message1.getVerifierPublicSessionKey());
            ECPoint sharedPoint = verifierSessionPublicKey.multiply(attesterSessionPrivateKey);
            BigInteger sharedSecret = sharedPoint.normalize().getXCoord().toBigInteger();
            SecretKey symmetricEncryptionKey = createSecretKey(sharedSecret.toString().toCharArray(), sessionPublicKeysHash);
            byte[] macKey = symmetricEncryptionKey.getEncoded();//sharedSecret.toByteArray();

            //checking validity of the message1
            SchnorrSignature signatureOfSessionKeys = message1.getSignatureOfSessionKeys();
            boolean isValidSessionSignature = signatureScheme.verifySignature(sessionPublicKeysHash, verifierPublicKey,
                    signatureScheme.decodePublicKey(signatureOfSessionKeys.getRandomPublicKey()),
                    new BigInteger(signatureOfSessionKeys.getSigma()));

            if (!isValidSessionSignature) {
                throw new IllegalStateException("Session keys signature is invalid");
            }

            System.out.println();
            boolean isValidMac = verifyMac(macKey, message1.getMac(), verifierSessionPublicKey.getEncoded(true),
                    verifierPublicKey.getEncoded(true), signatureOfSessionKeys.getRandomPublicKey(),
                    verifierPublicKey.getEncoded(true), signatureOfSessionKeys.getSigma());

            if (!isValidMac) {
                throw new IllegalStateException("Mac of message1 is invalid");
            }

            boolean isValidVerifierPublicKey = verifierPublicKey.equals(signatureScheme.decodePublicKey(message1.getVerifierPublicKey()));
            if (!isValidVerifierPublicKey) {
                throw new IllegalStateException("Verifier's public key is invalid");
            }

            //creating the message2
            byte[] anchor = computeHash(attesterSessionPublicKey.getEncoded(true),
                    verifierSessionPublicKey.getEncoded(true));
            Evidence evidence = new Evidence(anchor, waTZVersion, claim, attesterPublicKey.getEncoded(true));

            byte[] signingHash = computeHash(
                    anchor,
                    attesterPublicKey.getEncoded(true),
                    waTZVersion.getBytes(),
                    claim
            );
            BigInteger randomPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
            ECPoint randomPublicKey = curveGenerator.multiply(randomPrivateKey);
            SchnorrSignature signature = signatureScheme.computeSignature(signingHash, attesterPrivateKey,
                    attesterPublicKey, randomPrivateKey, randomPublicKey);

            byte[] mac = computeMac(
                    macKey,
                    attesterSessionPublicKey.getEncoded(true),
                    anchor,
                    attesterPublicKey.getEncoded(true),
                    waTZVersion.getBytes(),
                    claim
            );

            Message3 message3 = sendMessage2(attesterId, attesterSessionPublicKey.getEncoded(true),
                    evidence, signature, mac);
            byte[] decryptedData = decryptData(symmetricEncryptionKey, message3.getInitializationVector(),
                    message3.getEncryptedData());
            System.out.println("Verifier sent me: " + new String(decryptedData));
        } catch (IOException | SireException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public ECPoint getVerifierPublicKey() throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.GET_VERIFIER_PUBLIC_KEY)
                .build();
        this.oos.writeObject(msg);
        Object o = this.ois.readObject();
        if(o instanceof byte[]) {
            return curve.decodePoint((byte[]) o);
        }
        return null;
    }

    private static byte[] decryptData(SecretKey key, byte[] initializationVector, byte[] encryptedData) throws SireException {
        try {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(AES_KEY_LENGTH, initializationVector);
            symmetricCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            return symmetricCipher.doFinal(encryptedData);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new SireException("Failed to decrypt data", e);
        }
    }

    private static byte[] computeHash(byte[]... contents) {
        for (byte[] content : contents) {
            messageDigest.update(content);
        }
        return messageDigest.digest();
    }

    private static SecretKey createSecretKey(char[] password, byte[] salt) throws InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password, salt, 65536, AES_KEY_LENGTH);
        return new SecretKeySpec(secretKeyFactory.generateSecret(spec).getEncoded(), "AES");
    }



    private static boolean verifyMac(byte[] secretKey, byte[] mac, byte[]... contents) {
        return Arrays.equals(computeMac(secretKey, contents), mac);
    }

    private static byte[] computeMac(byte[] secretKey, byte[]... contents) {
        macEngine.init(new KeyParameter(secretKey));
        for (byte[] content : contents) {
            macEngine.update(content, 0, content.length);
        }
        byte[] mac = new byte[macEngine.getMacSize()];
        macEngine.doFinal(mac, 0);
        return mac;
    }

    private static BigInteger getRandomNumber(BigInteger field) {
        BigInteger rndBig = new BigInteger(field.bitLength() - 1, rndGenerator);
        if (rndBig.compareTo(BigInteger.ZERO) == 0) {
            rndBig = rndBig.add(BigInteger.ONE);
        }

        return rndBig;
    }

    //TODO turn attesterId into hash of Ga
    public Message1 join(String appId, String attesterId, byte[] attesterSessionPubKey) throws SireException, IOException, ClassNotFoundException {
        ProtoMessage0 msg0 = ProtoMessage0.newBuilder()
                .setAttesterId(attesterId)
                .setAppId(appId)
                .setAttesterPubSesKey(ByteString.copyFrom(attesterSessionPubKey))
                .build();

        System.out.println("Joining!");


        //this.dos.write(msg0.toByteArray());
        this.oos.writeObject(msg0);
        Object o = this.ois.readObject();
        ProtoMessage1 msg1 = null;
        if(o instanceof ProtoMessage1)
            msg1 = (ProtoMessage1) o;

        //ProtoMessage1 msg1 = proxy.join(appId, attesterId, msg0);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Message1 result = new Message1(byteStringToByteArray(out, msg1.getVerifierPubSesKey()),
                byteStringToByteArray(out, msg1.getVerifierPubKey()),
                protoToSchnorr(msg1.getSignatureSessionKeys()),
                byteStringToByteArray(out, msg1.getMac()));
        out.close();
        System.out.println("Message 1 received!");
        return result;
    }

    //TODO turn attesterId into hash of Ga
    public Message3 sendMessage2(String attesterId, byte[] attesterSessionPubKey, Evidence evidence, SchnorrSignature sign, byte[] mac)
            throws IOException, ClassNotFoundException {
        System.out.println("Sending Message 2!");
        ProtoMessage2 msg2 = ProtoMessage2.newBuilder()
                .setAttesterPubSesKey(ByteString.copyFrom(attesterSessionPubKey))
                .setEvidence(evidenceToProto(evidence))
                .setSignatureEvidence(schnorrToProto(sign))
                .setMac(ByteString.copyFrom(mac))
                .setAttesterId(attesterId)
                .build();

/*        this.dos.write(msg2.toByteArray());
        byte[] b = this.dis.readAllBytes();*/
        this.oos.writeObject(msg2);
        Object o = this.ois.readObject();//deserialize(b);
        ProtoMessage3 msg3 = null;
        if(o instanceof ProtoMessage3)
            msg3 = (ProtoMessage3) o;

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        //ProtoMessage3 msg3 = proxy.processMessage2(attesterId, msg2);

        Message3 result = new Message3(byteStringToByteArray(out, msg3.getIv()),
                byteStringToByteArray(out, msg3.getEncryptedData()));
        out.close();

        System.out.println("Message 2 received!");

        return result;
    }



    public void close() throws IOException {
        this.s.close();
        //this.proxy.close();
    }



    public void put(String appId, String key, byte[] value) throws IOException {
        //proxy.put(appId, key, value);
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_PUT)
                .setAppId(appId)
                .setKey(key)
                .setValue(ByteString.copyFrom(value))
                .build();
        this.oos.writeObject(msg);
        //this.dos.write(serialize(msg));
    }


    public void delete(String appId, String key) throws IOException {
        //proxy.delete(appId, key);
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_DELETE)
                .setAppId(appId)
                .setKey(key)
                .build();
        this.oos.writeObject(msg);
        //this.dos.write(serialize(msg));
    }


    public byte[] getData(String appId, String key) throws IOException, ClassNotFoundException {
        //return proxy.getData(appId, key);
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_GET)
                .setAppId(appId)
                .setKey(key)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
        //byte[] b = this.dis.readAllBytes();
        Object o = this.ois.readObject();//deserialize(b);
        if(o instanceof ProxyResponse pr) {
            //System.out.println("I'm in!");
            if(pr.getValue().equals(ByteString.EMPTY))
                return null;
            else {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                return byteStringToByteArray(out, pr.getValue());
            }
        }
        return null;
    }


    public List<byte[]> getList(String appId) throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_LIST)
                .setAppId(appId)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
        //byte[] b = this.dis.readAllBytes();
        Object o = this.ois.readObject();//deserialize(b);
        if(o instanceof ProxyResponse) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            List<ByteString> res = ((ProxyResponse) o).getListList();
            ArrayList<byte[]> tmp = new ArrayList<>();
            //System.out.println("List size: " + res.size());
            for(ByteString b : res)
                tmp.add(byteStringToByteArray(out, b));
            return tmp;
            //return byteStringToByteArray(out,((ProxyResponse) o).getValue());
        }
        return null;
    }


    public void cas(String appId, String key, byte[] oldData, byte[] newData) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_CAS)
                .setAppId(appId)
                .setKey(key)
                .setValue(ByteString.copyFrom(newData))
                .setOldData(ByteString.copyFrom(oldData))
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
    }

    public void leave(String appId, String deviceId) throws IOException, InterruptedException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.LEAVE)
                .setAppId(appId)
                .setDeviceId(deviceId)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
    }

    public void ping(String appId, String deviceId) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.PING)
                .setAppId(appId)
                .setDeviceId(deviceId)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
    }

    public List<DeviceContext> getView(String appId) throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.VIEW)
                .setAppId(appId)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);

        Object o = this.ois.readObject();//deserialize(b);
        if(o instanceof ProxyResponse) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            List<ProxyResponse.ProtoDeviceContext> res = ((ProxyResponse) o).getMembersList();
            ArrayList<DeviceContext> tmp = new ArrayList<>();
            //System.out.println("List size: " + res.size());
            for(ProxyResponse.ProtoDeviceContext d : res)
                tmp.add(new DeviceContext(d.getDeviceId(), new Timestamp(d.getTime().getSeconds() * 1000)));
            return tmp;
            //return byteStringToByteArray(out,((ProxyResponse) o).getValue());
        }
        return null;
    }
}
