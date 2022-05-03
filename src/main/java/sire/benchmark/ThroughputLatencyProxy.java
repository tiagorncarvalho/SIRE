package sire.benchmark;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import sire.attestation.DeviceEvidence;
import sire.attestation.Evidence;
import sire.messages.Messages;
import sire.proxy.*;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.AttesterContext;
import sire.serverProxyUtils.DeviceContext;
import sire.serverProxyUtils.SireException;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;

import static sire.messages.ProtoUtils.*;

public class ThroughputLatencyProxy {
    private final Logger logger = LoggerFactory.getLogger("sire");
    private static final int AES_KEY_LENGTH = 128;
    private final ConfidentialServiceProxy serviceProxy;
    private final MessageDigest messageDigest;
    private final ECPoint verifierPublicKey;
    private final SchnorrSignatureScheme signatureScheme;
    private final Map<String, AttesterContext> attesters;
    private final SecureRandom rndGenerator = new SecureRandom("sire".getBytes());
    private final CMac macEngine;
    private final SecretKeyFactory secretKeyFactory;
    private final ECPoint curveGenerator;
    private final Cipher symmetricCipher;
    private final int proxyId;

    //For throughput measurement
    private long startTime;
    private long numRequests;
    private  int numSenders;
    private double maxThroughput;


    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: sire.benchmark.ThroughputLatencyProxy <proxy id>");
            System.exit(-1);
        }
        ThroughputLatencyProxy proxy = null;
        try {
            int proxyId = Integer.parseInt(args[0]);
            proxy = new ThroughputLatencyProxy(proxyId);
        } catch (SireException e) {
            e.printStackTrace();
        }
        proxy.run();
    }

    public ThroughputLatencyProxy (int proxyId) throws SireException {
        System.out.println("Starting proxy!");
        this.proxyId = proxyId;
        //senders = new HashSet<>(3000);
        try {
            ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
            serviceProxy = new ConfidentialServiceProxy(proxyId, responseHandler);
        } catch (SecretSharingException e) {
            throw new SireException("Failed to contact the distributed verifier", e);
        }
        //System.out.println("Created serviceProxy!");
        try {
            messageDigest = MessageDigest.getInstance("SHA256");
            BlockCipher aes = new AESEngine();

            macEngine = new CMac(aes);
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            signatureScheme = new SchnorrSignatureScheme();
            curveGenerator = signatureScheme.getGenerator();
            symmetricCipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SireException("Failed to initialize cryptographic tools", e);
        }
        //System.out.println("Sending getKey message!");
        Response response;
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.ATTEST_GENERATE_SIGNING_KEY)
                    .build();
            byte[] b = msg.toByteArray();
            response = serviceProxy.invokeOrdered(b);//new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
        } catch (SecretSharingException e) {
            throw new SireException("Failed to obtain verifier's public key", e);
        }
        verifierPublicKey = signatureScheme.decodePublicKey(response.getPainData());
        //System.out.println("Received key!");

        attesters = new HashMap<>();
        startTime = System.nanoTime();
        System.out.println("Proxy is ready");
    }

    public void run() {
        try {
            ServerSocket ss = new ServerSocket(2500 + this.proxyId);
            System.out.println(2500 + this.proxyId);
            Socket s;
            Object socketLock = new Object();
            while(true) {
                synchronized (socketLock) {
                    s = ss.accept();
                }
                System.out.println("New client!");
                numSenders++;
                new ThroughputLatencyProxyThread(s).start();
                System.out.println("Connection accepted");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private class ThroughputLatencyProxyThread extends Thread {

        private final Socket s;

        public ThroughputLatencyProxyThread(Socket s) {
            this.s = s;
            System.out.println("Proxy Thread started!");
        }
        @Override
        public void run() {
            try {
                ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
                ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

                while (!s.isClosed()) {
                    Object o;
                    while ((o = ois.readObject()) != null) {
                        System.out.println("Object received! " + o);
                        numRequests++;
                        if (o instanceof Messages.ProtoMessage0 msg0) {
                            Messages.ProtoMessage1 msg1 = joins(msg0);
                            oos.writeObject(msg1);
                        } else if (o instanceof Messages.ProtoMessage2 msg2) {
                            Messages.ProtoMessage3 msg3 = processMessage2(msg2);
                            oos.writeObject(msg3);
                        } else if (o instanceof Messages.ProxyMessage msg) {
                            if (msg.getOperation() == Messages.ProxyMessage.Operation.GET_VERIFIER_PUBLIC_KEY) {
                                oos.writeObject(SchnorrSignatureScheme.encodePublicKey(verifierPublicKey));
                            }
                            else {
                                Messages.ProxyResponse result = runProxyMessage(msg);
                                if(result != null)
                                    oos.writeObject(result);
                            }
                        }
                        printMeasurement();
                    }
                }
            } catch (IOException | ClassNotFoundException | SireException | SecretSharingException e) {
                //e.printStackTrace();
            }
        }

        private Messages.ProxyResponse runProxyMessage(Messages.ProxyMessage msg) throws IOException, SecretSharingException, ClassNotFoundException {
            Response res = serviceProxy.invokeOrdered(msg.toByteArray());
            return switch(msg.getOperation()) {
                case MAP_GET -> mapGet(res);
                case MAP_LIST -> mapList(res);
                case MEMBERSHIP_VIEW -> memberView(res);
                case EXTENSION_GET -> extGet(res);
                case POLICY_GET -> policyGet(res);
                default -> null;
            };
        }

        private Messages.ProxyResponse policyGet(Response res) throws IOException, ClassNotFoundException {
            byte[] tmp = res.getPainData();
            if (tmp != null) {
                return Messages.ProxyResponse.newBuilder()
                        .setType(Messages.ProxyResponse.ResponseType.POLICY_GET)
                        .setPolicy((String) deserialize(tmp))
                        .build();
            } else {
                return Messages.ProxyResponse.newBuilder().build();
            }

        }

        private Messages.ProxyResponse extGet(Response res) throws IOException, ClassNotFoundException {
            byte[] tmp = res.getPainData();
            if (tmp != null) {
                return Messages.ProxyResponse.newBuilder()
                        .setType(Messages.ProxyResponse.ResponseType.EXTENSION_GET)
                        .setExtension((String) deserialize(tmp))
                        .build();
            } else {
                return Messages.ProxyResponse.newBuilder().build();
            }
        }

        private Messages.ProxyResponse memberView(Response res) throws IOException, ClassNotFoundException {
            byte[] tmp = res.getPainData();
            Messages.ProxyResponse.Builder prBuilder = Messages.ProxyResponse.newBuilder();
            if (tmp != null) {
                ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
                ObjectInputStream oin = new ObjectInputStream(bin);
                List<DeviceContext> members = (List<DeviceContext>) oin.readObject();
                for (DeviceContext d : members)
                    prBuilder.addMembers(Messages.ProxyResponse.ProtoDeviceContext.newBuilder()
                            .setDeviceId(d.getDeviceId())
                            .setTime(Timestamp.newBuilder()
                                    .setSeconds(d.getLastPing().getTime() / 1000)
                                    .build())
                            .build());
            }
            return prBuilder.build();
        }

        private Messages.ProxyResponse mapList(Response res) throws IOException, ClassNotFoundException {
            byte[] tmp = res.getPainData();
            Messages.ProxyResponse.Builder prBuilder = Messages.ProxyResponse.newBuilder();
            if (tmp != null) {
                ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
                ObjectInputStream oin = new ObjectInputStream(bin);
                ArrayList<byte[]> lst = (ArrayList<byte[]>) oin.readObject();
                //System.out.println("List size: " + lst.size());
                for (byte[] b : lst)
                    prBuilder.addList(ByteString.copyFrom(b));
            }
            return prBuilder.build();
        }

        private Messages.ProxyResponse mapGet(Response res) {
            byte[] tmp = res.getPainData();
            if (tmp != null) {
                return Messages.ProxyResponse.newBuilder()
                        .setValue(ByteString.copyFrom(tmp))
                        .build();
            } else {
                return Messages.ProxyResponse.newBuilder().build();
            }
        }

        public Messages.ProtoMessage1 processMessage0(Messages.ProtoMessage0 msg0) throws SireException {
            try {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ECPoint attesterSessionPublicKey = signatureScheme.decodePublicKey(byteStringToByteArray(out, msg0.getAttesterPubSesKey()));
                BigInteger mySessionPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
                ECPoint mySessionPublicKey = curveGenerator.multiply(mySessionPrivateKey);
                ECPoint sharedPoint = attesterSessionPublicKey.multiply(mySessionPrivateKey);
                BigInteger sharedSecret = sharedPoint.normalize().getXCoord().toBigInteger(); //TODO have to use key derivation algorithm

                byte[] sessionPublicKeysHash = computeHash(mySessionPublicKey.getEncoded(true),
                        attesterSessionPublicKey.getEncoded(true));

                SecretKey symmetricEncryptionKey = createSecretKey(sharedSecret.toString().toCharArray(), sessionPublicKeysHash);
                byte[] macKey = symmetricEncryptionKey.getEncoded();

                SchnorrSignature signature = getSignatureFromVerifier(sessionPublicKeysHash);
                Messages.ProtoSchnorr protoSign = schnorrToProto(signature);


                byte[] mac = computeMac(macKey, mySessionPublicKey.getEncoded(true),
                        verifierPublicKey.getEncoded(true), signature.getRandomPublicKey(),
                        signature.getSigningPublicKey(), signature.getSigma());

                AttesterContext newAttester = new AttesterContext(msg0.getAttesterId(), mySessionPrivateKey,
                        mySessionPublicKey,
                        attesterSessionPublicKey, symmetricEncryptionKey, macKey);
                attesters.put(newAttester.getAttesterId(), newAttester);

                Messages.ProtoMessage1 msg1 = Messages.ProtoMessage1.newBuilder()
                        .setVerifierPubSesKey(ByteString.copyFrom(mySessionPublicKey.getEncoded(true)))
                        .setVerifierPubKey(ByteString.copyFrom(verifierPublicKey.getEncoded(true)))
                        .setSignatureSessionKeys(protoSign)
                        .setMac(ByteString.copyFrom(mac))
                        .build();

                out.close();

                return msg1;
            } catch (InvalidKeySpecException | IOException e) {
                throw new SireException("Failed to create shared key", e);
            }
        }
        public Messages.ProtoMessage3 processMessage2(Messages.ProtoMessage2 msg2) throws SireException, IOException {
            AttesterContext attester = attesters.get(msg2.getAttesterId());
            if (attester == null)
                throw new SireException("Unknown attester id " + msg2.getAttesterId());

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ECPoint attesterSessionPublicKey = signatureScheme.decodePublicKey(byteStringToByteArray(out, msg2.getAttesterPubSesKey()));
            Evidence evidence = protoToEvidence(msg2.getEvidence());
            byte[] encodedAttestationServicePublicKey = evidence.getEncodedAttestationServicePublicKey();
            boolean isValidMac = verifyMac(
                    attester.getMacKey(),
                    byteStringToByteArray(out, msg2.getMac()),
                    byteStringToByteArray(out, msg2.getAttesterPubSesKey()),
                    evidence.getAnchor(),
                    encodedAttestationServicePublicKey,
                    evidence.getWaTZVersion().getBytes(),
                    evidence.getClaim()
            );

            if (!isValidMac)
                throw new SireException("Attester " + msg2.getAttesterId() + "'s mac is invalid");
            if (!attester.getAttesterSessionPublicKey().equals(attesterSessionPublicKey))
                throw new SireException("Attester " + msg2.getAttesterId() + "'s session public key is different");

            byte[] localAnchor = computeHash(attester.getAttesterSessionPublicKey().getEncoded(true),
                    attester.getMySessionPublicKey().getEncoded(true));
            if (!Arrays.equals(localAnchor, evidence.getAnchor()))
                throw new SireException("Anchor is different");

            DeviceEvidence deviceEvidence = new DeviceEvidence(evidence, protoToSchnorr(msg2.getSignatureEvidence()));

            Messages.ProxyMessage dataRequest = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.ATTEST_VERIFY)
                    .setEvidence(evidenceToProto(deviceEvidence.getEvidence()))
                    .setSignature(schnorrToProto(deviceEvidence.getEvidenceSignature()))
                    .build();

            try {
                Response dataResponse = serviceProxy.invokeOrdered(dataRequest.toByteArray());
                byte isValid = dataResponse.getPainData()[0];
                if (isValid == 0)
                    throw new SireException("Evidence is invalid");
                byte[] data = new byte[dataResponse.getPainData().length - 1];
                System.arraycopy(dataResponse.getPainData(), 1, data, 0, data.length);
                byte[] encryptedData = encryptData(attester.getSymmetricEncryptionKey(), data);
                byte[] initializationVector = symmetricCipher.getIV();

                return Messages.ProtoMessage3.newBuilder()
                        .setIv(ByteString.copyFrom(initializationVector))
                        .setEncryptedData(ByteString.copyFrom(encryptedData))
                        .build();

            } catch (SecretSharingException e) {
                throw new SireException("Failed to obtain data", e);
            }
        }

        private SecretKey createSecretKey(char[] password, byte[] salt) throws InvalidKeySpecException {
            KeySpec spec = new PBEKeySpec(password, salt, 65536, AES_KEY_LENGTH);
            return new SecretKeySpec(secretKeyFactory.generateSecret(spec).getEncoded(), "AES");
        }

        private byte[] encryptData(SecretKey key, byte[] data) throws SireException {
            try {
                symmetricCipher.init(Cipher.ENCRYPT_MODE, key);
                return symmetricCipher.doFinal(data);
            } catch (InvalidKeyException | IllegalBlockSizeException
                    | BadPaddingException e) {
                throw new SireException("Failed to encrypt data", e);
            }
        }

        private boolean verifyMac(byte[] secretKey, byte[] mac, byte[]... contents) {
            return Arrays.equals(computeMac(secretKey, contents), mac);
        }

        private SchnorrSignature getSignatureFromVerifier(byte[] data) throws SireException {

            Messages.ProxyMessage signingRequest = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.ATTEST_SIGN_DATA)
                    .setDataToSign(ByteString.copyFrom(data))
                    .build();
            UncombinedConfidentialResponse signatureResponse;
            try {
                signatureResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrdered2(signingRequest.toByteArray());
            } catch (SecretSharingException e) {
                throw new SireException("Verifier failed to sign", e);
            }

            PublicPartialSignature partialSignature;
            try (ByteArrayInputStream bis = new ByteArrayInputStream(signatureResponse.getPlainData());
                 ObjectInput in = new ObjectInputStream(bis)) {
                partialSignature = PublicPartialSignature.deserialize(signatureScheme, in);
            } catch (IOException | ClassNotFoundException e) {
                throw new SireException("Failed to deserialize public data of partial signatures");
            }

            EllipticCurveCommitment signingKeyCommitment = partialSignature.getSigningKeyCommitment();
            EllipticCurveCommitment randomKeyCommitment = partialSignature.getRandomKeyCommitment();
            ECPoint randomPublicKey = partialSignature.getRandomPublicKey();
            VerifiableShare[] verifiableShares = signatureResponse.getVerifiableShares()[0];
            Share[] partialSignatures = new Share[verifiableShares.length];
            for (int i = 0; i < verifiableShares.length; i++) {
                partialSignatures[i] = verifiableShares[i].getShare();
            }

            if (randomKeyCommitment == null)
                throw new IllegalStateException("Random key commitment is null");

            try {
                BigInteger sigma = signatureScheme.combinePartialSignatures(
                        serviceProxy.getCurrentF(),
                        data,
                        signingKeyCommitment,
                        randomKeyCommitment,
                        randomPublicKey,
                        partialSignatures
                );
                return new SchnorrSignature(sigma.toByteArray(), verifierPublicKey.getEncoded(true),
                        randomPublicKey.getEncoded(true));
            } catch (SecretSharingException e) {
                throw new SireException("Failed to combine partial signatures", e);
            }

        }

        private byte[] computeHash(byte[]... contents) {
            for (byte[] content : contents) {
                messageDigest.update(content);
            }
            return messageDigest.digest();
        }

        private byte[] computeMac(byte[] secretKey, byte[]... contents) {
            macEngine.init(new KeyParameter(secretKey));
            for (byte[] content : contents) {
                macEngine.update(content, 0, content.length);
            }
            byte[] mac = new byte[macEngine.getMacSize()];
            macEngine.doFinal(mac, 0);
            return mac;
        }

        private BigInteger getRandomNumber(BigInteger field) {
            BigInteger rndBig = new BigInteger(field.bitLength() - 1, rndGenerator);
            if (rndBig.compareTo(BigInteger.ZERO) == 0) {
                rndBig = rndBig.add(BigInteger.ONE);
            }

            return rndBig;
        }

        public void close() {
            serviceProxy.close();
        }

        public Messages.ProtoMessage1 joins(Messages.ProtoMessage0 msg) {
            try {
                Messages.ProxyMessage joinRequest = Messages.ProxyMessage.newBuilder()
                        .setOperation(Messages.ProxyMessage.Operation.MEMBERSHIP_JOIN)
                        .setAppId(msg.getAppId())
                        .setDeviceId(msg.getAttesterId())
                        .setDeviceType(msg.getType())
                        .build();
                serviceProxy.invokeOrdered(joinRequest.toByteArray());

                return processMessage0(msg);
            } catch (SecretSharingException | SireException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private void printMeasurement() {
        long currentTime = System.nanoTime();
        double deltaTime = (currentTime - startTime) / 1_000_000_000.0;
        if ((int) (deltaTime / 2) > 0) {
            long delta = currentTime - startTime;
            double throughput = numRequests / deltaTime;
            if (throughput > maxThroughput)
                maxThroughput = throughput;
            logger.info("M:(clients[#]|requests[#]|delta[ns]|throughput[ops/s]|max[ops/s])>({}|{}|{}|{}|{})",
                    numSenders, numRequests, delta, throughput, maxThroughput);
            numRequests = 0;
            startTime = currentTime;
        }
    }
}
