
package sire.benchmark;

import bftsmart.communication.ServerCommunicationSystem;
import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.core.messages.TOMMessage;
import com.google.protobuf.ByteString;
import confidential.ConfidentialMessage;
import confidential.facade.server.ConfidentialSingleExecutable;
import confidential.polynomial.DistributedPolynomialManager;
import confidential.polynomial.RandomKeyPolynomialListener;
import confidential.polynomial.RandomPolynomialContext;
import confidential.polynomial.RandomPolynomialListener;
import confidential.server.ConfidentialRecoverable;
import confidential.statemanagement.ConfidentialSnapshot;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sire.attestation.DeviceEvidence;
import sire.attestation.VerifierManager;
import sire.coordination.CoordinationManager;
import sire.membership.MembershipManager;
import sire.messages.Messages;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.SireException;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.commitment.linear.LinearCommitments;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.sql.Timestamp;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static sire.messages.ProtoUtils.*;

public class ThroughputLatencyVerifierServer implements ConfidentialSingleExecutable, RandomPolynomialListener, RandomKeyPolynomialListener {
    private final Logger logger = LoggerFactory.getLogger("sire");
    private final ServerCommunicationSystem serverCommunicationSystem;
    private final DistributedPolynomialManager distributedPolynomialManager;
    private final ServiceReplica serviceReplica;
    private final ConfidentialRecoverable cr;

    //used during requests and data map access
    private final Lock lock;
    private final int id;

    //used to store requests asking for a random number
    private Map<Integer, MessageContext> requests;// <polynomial id, MessageContext>
    //used to store random number's shares of clients
    private Map<Integer, VerifiableShare> data;// <client id, random number's share>

    //used to store requests asking for generation of a signing key
    private final LinkedList<MessageContext> signingKeyRequests;
    private int signingKeyGenerationId;

    //used to store requests asking for generation of a signature
    private final Map<Integer, MessageContext> signingRequestContexts;// <polynomial id, MessageContext>
    //used to store data for signing
    private final Map<Integer, byte[]> signingData;// <client id, data for signing>

    private final SchnorrSignatureScheme schnorrSignatureScheme;

    private VerifiableShare verifierSigningPrivateKeyShare;
    private ECPoint verifierSigningPublicKey;

    //private final ECPoint dummyAttesterPublicKey;

    //key value store for information concerning devices, applications and more
    //private final Map<String, byte[]> storage;
    private final CoordinationManager storage;

    //key value store for membership state, key = appId
    //private final Map<String, AppContext> membership;
    private final MembershipManager membership;

    //runs and stores extensions
    MessageDigest messageDigest;

    //verifies the evidence
    private final VerifierManager verifierManager;

    private final int timebound = 500; //in milliseconds
    private final Map<String, Timestamp> devicesTimestamps;


    //For throughput measurement
    private long startTime;
    private long numRequests;
    private final Set<Integer> senders;
    private double maxThroughput;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        if (args.length < 1) {
            System.out.println("Usage: sire.server.SireServer <server id>");
            System.exit(-1);
        }

        new ThroughputLatencyVerifierServer(Integer.parseInt(args[0]));
    }

    public ThroughputLatencyVerifierServer(int id) throws NoSuchAlgorithmException {
        this.id = id;
        senders = new HashSet<>(3000);
        lock = new ReentrantLock(true);
        requests = new TreeMap<>();
        data = new TreeMap<>();
        storage = new CoordinationManager();
        membership = new MembershipManager();
        signingKeyRequests = new LinkedList<>();
        signingRequestContexts = new TreeMap<>();
        signingData = new TreeMap<>();
        cr = new ConfidentialRecoverable(id, this);
        serviceReplica = new ServiceReplica(id, cr, cr, null, null, null, null, cr);
        verifierManager = new VerifierManager();
        serverCommunicationSystem = serviceReplica.getServerCommunicationSystem();
        distributedPolynomialManager = cr.getDistributedPolynomialManager();
        distributedPolynomialManager.setRandomPolynomialListener(this);
        distributedPolynomialManager.setRandomKeyPolynomialListener(this);
        schnorrSignatureScheme = new SchnorrSignatureScheme();
        messageDigest = MessageDigest.getInstance("SHA256");
        devicesTimestamps = new TreeMap<>();

        startTime = System.nanoTime();
    }

    @Override
    public ConfidentialMessage appExecuteOrdered(byte[] bytes, VerifiableShare[] verifiableShares, MessageContext messageContext) {
        numRequests++;
        senders.add(messageContext.getSender());
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.parseFrom(bytes);
            Messages.ProxyMessage.Operation op = msg.getOperation();

            if(op.toString().startsWith("MAP"))
                return executeOrderedMap(msg);
            else if(op.toString().startsWith("TIMESTAMP"))
                return executeOrderedTimestamp(msg, messageContext);
            else if(op.toString().startsWith("MEMBERSHIP"))
                return executeOrderedMembership(msg, messageContext);
            else if(op.toString().startsWith("ATTEST"))
                return executeOrderedAttestation(msg, messageContext);
        } catch (IOException | SireException e) {
            e.printStackTrace();
        } finally {
            printMeasurement();
        }
        return null;
    }

    @Override
    public ConfidentialMessage appExecuteUnordered(byte[] bytes, VerifiableShare[] verifiableShares, MessageContext messageContext) {
        numRequests++;
        senders.add(messageContext.getSender());
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.parseFrom(bytes);
            Messages.ProxyMessage.Operation op = msg.getOperation();

            if(op.toString().startsWith("MAP"))
                return executeOrderedMap(msg);
            else if(op.toString().startsWith("TIMESTAMP"))
                return executeOrderedTimestamp(msg, messageContext);
            else if(op.toString().startsWith("MEMBERSHIP"))
                return executeOrderedMembership(msg, messageContext);
            else if(op.toString().startsWith("ATTEST"))
                return executeOrderedAttestation(msg, messageContext);
        } catch (IOException | SireException e) {
            e.printStackTrace();
        } finally {
            printMeasurement();
        }
        return null;
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
                    senders.size(), numRequests, delta, throughput, maxThroughput);
            numRequests = 0;
            startTime = currentTime;
            senders.clear();
        }
    }

    private ConfidentialMessage executeOrderedAttestation(Messages.ProxyMessage msg, MessageContext messageContext) throws IOException {
        Messages.ProxyMessage.Operation op = msg.getOperation();
        if (op == Messages.ProxyMessage.Operation.ATTEST_GET_PUBLIC_KEY) {
            try {
                lock.lock();
                if (verifierSigningPrivateKeyShare == null && signingKeyRequests.isEmpty()) {
                    signingKeyRequests.add(messageContext);
                    generateSigningKey();
                } else if (verifierSigningPrivateKeyShare != null) {
                    logger.warn("I already have a signing key.");
                    System.out.println("Signing key already created...");
                    return new ConfidentialMessage(verifierSigningPublicKey.getEncoded(true));
                } else {
                    logger.warn("Signing key is being created.");
                }
            } finally {
                lock.unlock();
            }
        }
        return null;
    }

    private ConfidentialMessage executeOrderedTimestamp(Messages.ProxyMessage msg, MessageContext messageContext) throws IOException, SireException {
        Messages.ProxyMessage.Operation op = msg.getOperation();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Timestamp ts = new Timestamp(messageContext.getTimestamp());
        Messages.ProxyResponse response;
        switch(op) {
            case TIMESTAMP_GET -> {
                lock.lock();
                response = Messages.ProxyResponse.newBuilder()
                        .setTimestamp(ByteString.copyFrom(serialize(ts)))
                        .build();
                lock.unlock();
                return new ConfidentialMessage(response.toByteArray());
            }
            case ATTEST_TIMESTAMP -> {
                lock.lock();
                SchnorrSignature sign = protoToSchnorr(msg.getSignature());
                boolean isValid = schnorrSignatureScheme.verifySignature(computeHash(byteStringToByteArray(baos, msg.getPubKey())),
                        schnorrSignatureScheme.decodePublicKey(byteStringToByteArray(baos, msg.getPubKey())),
                        schnorrSignatureScheme.decodePublicKey(sign.getRandomPublicKey()), new BigInteger(sign.getSigma()));
                if(isValid) {
                    //byte[] data = concat(serialize(ts), byteStringToByteArray(baos, msg.getPubKey()));
                    devicesTimestamps.put(msg.getDeviceId(), ts);
                    response = Messages.ProxyResponse.newBuilder()
                            .setTimestamp(ByteString.copyFrom(serialize(ts)))
                            .setPubKey(msg.getPubKey())
                            //.setSign()
                            .build();
                    baos.close();
                    lock.unlock();

                    return new ConfidentialMessage(response.toByteArray());
					/*
					signingData.put(messageContext.getSender(), data);
					System.out.println(Arrays.toString(data));
					generateRandomKey(messageContext);*/

                } else {
                    throw new SireException("Invalid signature!");
                }
            }
        }
        return null;
    }

    private ConfidentialMessage executeOrderedMembership(Messages.ProxyMessage msg, MessageContext messageContext) throws IOException, SireException {
        Messages.ProxyMessage.Operation op = msg.getOperation();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if(op != Messages.ProxyMessage.Operation.MEMBERSHIP_JOIN && membership.isDeviceValid(msg.getAppId(), msg.getDeviceId()))
            throw new SireException("Unknown Device: Not attested or not in this app membership.");
        switch(op) {
            case MEMBERSHIP_JOIN -> {
                DeviceEvidence deviceEvidence = new DeviceEvidence(protoToEvidence(msg.getEvidence()),
                        protoToSchnorr(msg.getSignature()));
                boolean isValidEvidence = verifierManager.verifyEvidence(msg.getAppId(), deviceEvidence,
                        byteStringToByteArray(baos, msg.getTimestamp()));
                boolean isTimedout = (new Timestamp(messageContext.getTimestamp())).before(
                        new Timestamp(devicesTimestamps.get(msg.getDeviceId()).getTime() + timebound));

                if (isValidEvidence && isTimedout) {
                    Messages.ProxyResponse res = Messages.ProxyResponse.newBuilder()
                            .setTimestamp(ByteString.copyFrom(serialize(new Timestamp(messageContext.getTimestamp()))))
                            .setHash(ByteString.copyFrom(computeHash(msg.toByteArray())))
                            .setPubKey(msg.getPubKey())
                            //.setSign()
                            .build();
                    membership.join(msg.getAppId(), msg.getDeviceId(), new Timestamp(messageContext.getTimestamp()),
                            protoDevToDev(msg.getDeviceType()));

                    return new ConfidentialMessage(res.toByteArray());
                } else {
                    return new ConfidentialMessage(new byte[]{0});
                }
            }
        }
        return null;
    }

    private ConfidentialMessage executeOrderedMap(Messages.ProxyMessage msg) throws IOException, SireException {
        Messages.ProxyMessage.Operation op = msg.getOperation();
        switch(op) {
            case MAP_PUT -> {
                lock.lock();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] value = byteStringToByteArray(out, msg.getValue());
                out.close();
                storage.put(msg.getAppId(), msg.getKey(), value);
                lock.unlock();

                return new ConfidentialMessage();
            }
            case MAP_GET -> {
                return new ConfidentialMessage(storage.get(msg.getAppId(), msg.getKey()));
            }
        }
        return null;
    }

/**
     * Method used to asynchronously send the random number share
     * @param receiverContext Information about the requesting client
     * @param share Random number share
     */

    public void sendRandomNumberShareTo(MessageContext receiverContext, VerifiableShare share) {
        ConfidentialMessage response = new ConfidentialMessage(null, share);//maybe send encrypted if needed (e.g., when tls encryption is off)
        sendResponseTo(receiverContext, response);
    }


/**
     * Method used to send a response to a client
     * @param receiverContext Information about the requesting client
     * @param response The response
     */

    public void sendResponseTo(MessageContext receiverContext, ConfidentialMessage response) {
        TOMMessage tomMessage = new TOMMessage(
                id,
                receiverContext.getSession(),
                receiverContext.getSequence(),
                receiverContext.getOperationId(),
                response.serialize(),
                serviceReplica.getReplicaContext().getSVController().getCurrentViewId(),
                receiverContext.getType()
        );
        serverCommunicationSystem.send(new int[]{receiverContext.getSender()}, tomMessage);
    }



    /**
     * Method called by the polynomial generation manager when the requested random number is generated
     * @param context Random number share and its context
     */

    @Override
    public void onRandomPolynomialsCreation(RandomPolynomialContext context) {
        lock.lock();
        double delta = context.getTime() / 1_000_000.0;
        logger.debug("Received random number polynomial with id {} in {} ms", context.getInitialId(), delta);
        MessageContext messageContext = requests.remove(context.getInitialId());
        data.put(messageContext.getSender(), context.getPoint());
        logger.debug("Sending random number share to {}", messageContext.getSender());
        sendRandomNumberShareTo(messageContext, context.getPoint());
        lock.unlock();
    }

    private void onRandomKey(int id, VerifiableShare privateKeyShare, ECPoint publicKey) {
        if (signingRequestContexts.containsKey(id)) {
            logger.info("Received random signing key");
            MessageContext messageContext = signingRequestContexts.remove(id);
            signAndSend(messageContext, signingData.remove(messageContext.getSender()), verifierSigningPrivateKeyShare,
                    privateKeyShare, publicKey);
        } else if (signingKeyGenerationId == id) {
            logger.info("Received service signing key");
            verifierSigningPrivateKeyShare = privateKeyShare;
            verifierSigningPublicKey = publicKey;
            for (MessageContext messageContext : signingKeyRequests) {
                sendPublicKeyTo(messageContext, publicKey);
            }
            signingKeyRequests.clear();
        } else {
            logger.info("Received an unknown polynomial id {}", id);
        }
    }

    private void sendPublicKeyTo(MessageContext receiverContext, ECPoint publicKey) {
        byte[] encodedPublicKey = publicKey.getEncoded(true);
        ConfidentialMessage response = new ConfidentialMessage(encodedPublicKey);
        sendResponseTo(receiverContext, response);
    }

    private void signAndSend(MessageContext receiverContext, byte[] data, VerifiableShare signingPrivateKeyShare,
                             VerifiableShare randomPrivateKeyShare, ECPoint randomPublicKey) {
        BigInteger sigma = schnorrSignatureScheme.computePartialSignature(data,
                signingPrivateKeyShare.getShare().getShare(), randomPrivateKeyShare.getShare().getShare(), randomPublicKey);
        byte[] plainData = null;
        PublicPartialSignature publicPartialSignature = new PublicPartialSignature(
                (EllipticCurveCommitment) signingPrivateKeyShare.getCommitments(),
                (EllipticCurveCommitment) randomPrivateKeyShare.getCommitments(), randomPublicKey);
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            publicPartialSignature.serialize(out);

            out.flush();
            bos.flush();
            plainData = bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        BigInteger shareholder = cr.getShareholderId();
        if (serviceReplica.getId() == 0)
            sigma = sigma.add(BigInteger.ONE);
        VerifiableShare partialSignature = new VerifiableShare(new Share(shareholder, sigma),
                new LinearCommitments(BigInteger.ZERO), null);
        ConfidentialMessage response = new ConfidentialMessage(plainData, partialSignature);
        sendResponseTo(receiverContext, response);
    }


/**
     * Method called by the polynomial generation manager when the requested random key is generated
     * @param context Random number share and its context
     */

    @Override
    public void onRandomKeyPolynomialsCreation(RandomPolynomialContext context) {
        lock.lock();
        VerifiableShare privateKeyShare = context.getPoint();
        ECPoint[] commitment = ((EllipticCurveCommitment)context.getPoint().getCommitments()).getCommitment();
        ECPoint publicKey = commitment[commitment.length - 1];
        onRandomKey(context.getInitialId(), privateKeyShare, publicKey);
        lock.unlock();
    }



    @Override
    public ConfidentialSnapshot getConfidentialSnapshot() {
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bout)) {
            out.writeInt(requests.size());
            for (Map.Entry<Integer, MessageContext> entry : requests.entrySet()) {
                out.writeInt(entry.getKey());
                out.writeObject(entry.getValue());
            }
            out.writeInt(data.size());
            VerifiableShare[] shares = new VerifiableShare[data.size()];
            int index = 0;
            for (Map.Entry<Integer, VerifiableShare> entry : data.entrySet()) {
                out.writeInt(entry.getKey());
                entry.getValue().writeExternal(out);
                shares[index++] = entry.getValue();
            }
            out.flush();
            bout.flush();
            return new ConfidentialSnapshot(bout.toByteArray(), shares);
        } catch (IOException e) {
            logger.error("Error while taking snapshot", e);
        }
        return null;
    }

    @Override
    public void installConfidentialSnapshot(ConfidentialSnapshot confidentialSnapshot) {
        try (ByteArrayInputStream bin = new ByteArrayInputStream(confidentialSnapshot.getPlainData());
             ObjectInput in = new ObjectInputStream(bin)) {
            int size = in.readInt();
            requests = new TreeMap<>();
            while (size-- > 0) {
                int key = in.readInt();
                MessageContext value = (MessageContext) in.readObject();
                requests.put(key, value);
            }
            size = in.readInt();
            data = new TreeMap<>();
            VerifiableShare[] shares = confidentialSnapshot.getShares();
            for (int i = 0; i < size; i++) {
                int key = in.readInt();
                VerifiableShare value = shares[i];
                value.readExternal(in);
                data.put(key, value);
            }
        } catch (IOException | ClassCastException | ClassNotFoundException e) {
            logger.error("Error while installing snapshot", e);
        }
    }

    private byte[] computeHash(byte[]... contents) {
        for (byte[] content : contents) {
            messageDigest.update(content);
        }
        return messageDigest.digest();
    }

    private void generateSigningKey() {
        signingKeyGenerationId = distributedPolynomialManager.createRandomKeyPolynomial(
                serviceReplica.getReplicaContext().getCurrentView().getF(),
                serviceReplica.getReplicaContext().getCurrentView().getProcesses());
    }

}
