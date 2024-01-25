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

package sire.device;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import sire.attestation.Evidence;
import sire.messages.Messages.*;
import static sire.messages.ProtoUtils.*;
import com.google.protobuf.ByteString;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.membership.DeviceContext;
import sire.serverProxyUtils.SireException;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

public class DeviceStub {
    Socket s;
    ObjectOutputStream oos;
    ObjectInputStream ois;
    private final BigInteger order;
    private final ECCurve curve;
    private static final int AES_KEY_LENGTH = 128;
    private static final SecureRandom rndGenerator = new SecureRandom("sire".getBytes());
    private static CMac macEngine;
    private static SecretKeyFactory secretKeyFactory;
    private static Cipher symmetricCipher;
    private BigInteger attesterPrivateKey;
    private ECPoint attesterPublicKey;
    private Timestamp attestationTime;
    SchnorrSignatureScheme scheme;
    ECPoint verifierPublicKey;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    public DeviceStub() throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, ClassNotFoundException {
        String ip = "";
        Properties prop;
        int port = 0;
        try (InputStream input = new FileInputStream("config/proxy.properties")){
            prop = new Properties();
            prop.load(input);
            port = Integer.parseInt(prop.getProperty("port"));
            ip = prop.getProperty("ip");
        } catch(IOException e) {
            e.printStackTrace();
        }

        secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        macEngine = new CMac(new AESEngine());
        symmetricCipher = Cipher.getInstance("AES/GCM/NoPadding");
        BigInteger prime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
        BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
        scheme = new SchnorrSignatureScheme();
        BigInteger cofactor = prime.divide(order);
        curve = new ECCurve.Fp(prime, a, b, order, cofactor);

        try {
            this.s = new Socket(ip, port);
            this.oos = new ObjectOutputStream(s.getOutputStream());
            this.ois = new ObjectInputStream(s.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
        attesterPrivateKey = new BigInteger("4049546346519992604730332816858472394381393488413156548605745581385");
        attesterPublicKey = scheme.getGenerator().multiply(attesterPrivateKey);

        verifierPublicKey = getVerifierPublicKey();
    }

    public void attest(String appId, String version, byte[] claim) {
        try {
            ECPoint curveGenerator = scheme.getGenerator();

            BigInteger randomPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
            ECPoint randomPublicKey = curveGenerator.multiply(randomPrivateKey);
            SchnorrSignature signature = scheme.computeSignature(computeHash(attesterPublicKey.getEncoded(true)), attesterPrivateKey,
                    attesterPublicKey, randomPrivateKey, randomPublicKey);

            Timestamp ts = getTimestamp(signature); //used in message2


            //creating the message2
            Evidence evidence = new Evidence(version, claim, attesterPublicKey.getEncoded(true));
            Base64.Encoder enc = Base64.getEncoder();

            byte[] signingHash = computeHash(
                    attesterPublicKey.getEncoded(true),
                    version.getBytes(),
                    claim,
                    serialize(ts),
                    appId.getBytes()
            );
            randomPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
            randomPublicKey = curveGenerator.multiply(randomPrivateKey);
            signature = scheme.computeSignature(signingHash, attesterPrivateKey,
                    attesterPublicKey, randomPrivateKey, randomPublicKey);

            attestationTime = join(appId, evidence, ts, signature);

            System.out.println("Attested!");

        } catch (/*IOException | ClassNotFoundException*/ Exception e) {
            e.printStackTrace();
        }
    }

    /*public void cheatMethod() {
        ECPoint curveGenerator = scheme.getGenerator();
        byte[] signingHash = computeHash(
                attesterPublicKey.getEncoded(true),
                "1.0".getBytes(),
                "measure1".getBytes(),
                Base64.getDecoder().decode("rO0ABXNyABJqYXZhLnNxbC5UaW1lc3RhbXAmGNXIAVO/ZQIAAUkABW5hbm9zeHIADmphdmEudXRpbC5EYXRlaGqBAUtZdBkDAAB4cHcIAAABhnou7Ih4FyBpAA=="),
                "app1".getBytes()
        );
        BigInteger randomPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
        ECPoint randomPublicKey = curveGenerator.multiply(randomPrivateKey);
        SchnorrSignature signature = scheme.computeSignature(signingHash, attesterPrivateKey,
                attesterPublicKey, randomPrivateKey, randomPublicKey);
        Base64.Encoder enc = Base64.getEncoder();
        System.out.println(enc.encodeToString(signature.getSigma()));
        System.out.println();
        System.out.println(enc.encodeToString(signature.getSigningPublicKey()));
        System.out.println();
        System.out.println(enc.encodeToString(signature.getRandomPublicKey()));
    }*/

    public ECPoint getVerifierPublicKey() throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.ATTEST_GET_PUBLIC_KEY)
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

/*    private static SecretKey createSecretKey(char[] password, byte[] salt) throws InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password, salt, 65536, AES_KEY_LENGTH);
        return new SecretKeySpec(secretKeyFactory.generateSecret(spec).getEncoded(), "AES");
    }

    private static boolean verifyMac(byte[] secretKey, byte[] mac, byte[]... contents) {
        return Arrays.equals(computeMac(secretKey, contents), mac);
    }*/

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

    //Generic one
    private Timestamp getTimestamp(String appId) {
        try {
            ProxyMessage msg = ProxyMessage.newBuilder()
                    .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                    .setAppId(appId)
                    .setOperation(ProxyMessage.Operation.TIMESTAMP_GET)
                    .build();

            this.oos.writeObject(msg);

            Object o = this.ois.readObject();
            System.out.println("Response received!");
            if(o instanceof ProxyResponse) {
                ProxyResponse res = (ProxyResponse) o;
                return (Timestamp) deserialize(byteStringToByteArray(baos, res.getTimestamp()));
            }
            return null;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    //First step of attestation
    private Timestamp getTimestamp(SchnorrSignature sign) {
        try {
            ProxyMessage msg = ProxyMessage.newBuilder()
                    .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                    .setOperation(ProxyMessage.Operation.ATTEST_TIMESTAMP)
                    .setPubKey(ByteString.copyFrom(attesterPublicKey.getEncoded(true)))
                    .setSignature(schnorrToProto(sign))
                    .build();

            this.oos.writeObject(msg);

            Object o = this.ois.readObject();
            if(o instanceof ProxyResponse) {
                ProxyResponse res = (ProxyResponse) o;
                SchnorrSignature schnorrSignature = protoToSchnorr(res.getSign());
                boolean isSignatureValid = scheme.verifySignature(concat(byteStringToByteArray(baos, res.getTimestamp()),
                        byteStringToByteArray(baos, res.getPubKey())), scheme.decodePublicKey(schnorrSignature.getSigningPublicKey()),
                        scheme.decodePublicKey(schnorrSignature.getRandomPublicKey()), new BigInteger(schnorrSignature.getSigma()));


                return isSignatureValid ? (Timestamp) deserialize(byteStringToByteArray(baos, res.getTimestamp())) : null;
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] concat(byte[]...content) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for(byte[] b : content) {
            baos.write(b);
        }
        return baos.toByteArray();
    }

    private Timestamp join(String appId, Evidence evidence, Timestamp ts, SchnorrSignature sign)
            throws IOException, ClassNotFoundException {
        ProxyMessage joinMsg = ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(ProxyMessage.Operation.MEMBERSHIP_JOIN)
                .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                .setEvidence(evidenceToProto(evidence))
                .setTimestamp(ByteString.copyFrom(serialize(ts)))
                .setPubKey(ByteString.copyFrom(attesterPublicKey.getEncoded(true)))
                .setSignature(schnorrToProto(sign))
                .build();
        this.oos.writeObject(joinMsg);

        Object o = this.ois.readObject();
        if(o instanceof ProxyResponse) {
            ProxyResponse res = (ProxyResponse) o;
            byte[] hash = computeHash(joinMsg.toByteArray());
            SchnorrSignature schnorrSignature = protoToSchnorr(res.getSign());
            boolean isSignatureValid = scheme.verifySignature(computeHash(byteStringToByteArray(baos, res.getTimestamp()),
                            byteStringToByteArray(baos, res.getHash()), byteStringToByteArray(baos, res.getPubKey())),
                    scheme.decodePublicKey(schnorrSignature.getSigningPublicKey()),
                    scheme.decodePublicKey(schnorrSignature.getRandomPublicKey()), new BigInteger(schnorrSignature.getSigma()));

            boolean isHashValid = Arrays.equals(hash, byteStringToByteArray(baos, res.getHash()));

            return isSignatureValid && isHashValid ? (Timestamp) deserialize(byteStringToByteArray(baos, res.getTimestamp())) : null;
        }
        return null;
    }



    public void close() throws IOException {
        this.s.close();
    }



    public void put(String appId, String key, byte[] value) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_PUT)
                .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                .setAppId(appId)
                .setKey(key)
                .setValue(ByteString.copyFrom(value))
                .build();
        this.oos.writeObject(msg);
    }


    public void delete(String appId, String key) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_DELETE)
                .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                .setAppId(appId)
                .setKey(key)
                .build();
        this.oos.writeObject(msg);
    }


    public byte[] getData(String appId, String key) throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_GET)
                .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                .setAppId(appId)
                .setKey(key)
                .build();
        this.oos.writeObject(msg);
        Object o = this.ois.readObject();
        if(o instanceof ProxyResponse) {
            ProxyResponse res = (ProxyResponse) o;
            if(res.getValue().equals(ByteString.EMPTY))
                return null;
            else {
                return byteStringToByteArray(baos, res.getValue());
            }
        }
        return null;
    }


    public List<byte[]> getList(String appId) throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_LIST)
                .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                .setAppId(appId)
                .build();
        this.oos.writeObject(msg);
        Object o = this.ois.readObject();
        if(o instanceof ProxyResponse) {
            List<ByteString> res = ((ProxyResponse) o).getListList();
            ArrayList<byte[]> tmp = new ArrayList<>();
            for(ByteString b : res)
                tmp.add(byteStringToByteArray(baos, b));
            return tmp;
        }
        return null;
    }


    public void cas(String appId, String key, byte[] oldData, byte[] newData) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_CAS)
                .setAppId(appId)
                .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                .setKey(key)
                .setValue(ByteString.copyFrom(newData))
                .setOldData(ByteString.copyFrom(oldData))
                .build();
        this.oos.writeObject(msg);
    }

    public void leave(String appId) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MEMBERSHIP_LEAVE)
                .setAppId(appId)
                .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                .build();
        this.oos.writeObject(msg);
    }

    public void ping(String appId) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MEMBERSHIP_PING)
                .setAppId(appId)
                .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                .build();
        this.oos.writeObject(msg);
    }

    public List<DeviceContext> getView(String appId) throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MEMBERSHIP_VIEW)
                .setDeviceId(bytesToHex(computeHash(attesterPublicKey.getEncoded(true))))
                .setAppId(appId)
                .build();
        this.oos.writeObject(msg);

        Object o = this.ois.readObject();
        if(o instanceof ProxyResponse) {
            List<ProxyResponse.ProtoDeviceContext> res = ((ProxyResponse) o).getMembersList();
            ArrayList<DeviceContext> tmp = new ArrayList<>();
            /*for(ProxyResponse.ProtoDeviceContext d : res) {
                DeviceContext dev = new DeviceContext(d.getDeviceId(), new Timestamp(d.getTime().getSeconds() * 1000),
                        new Timestamp(d.getCertExpTime().getSeconds() * 1000));
                tmp.add(dev);
            }*/
            return tmp;
        }
        return null;
    }
}
