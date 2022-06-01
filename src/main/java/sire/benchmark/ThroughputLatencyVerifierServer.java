package sire.benchmark;

import bftsmart.communication.ServerCommunicationSystem;
import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.core.messages.TOMMessage;
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
import sire.configuration.ExtensionManager;
import sire.configuration.ExtensionType;
import sire.messages.Messages;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.AppContext;
import sire.serverProxyUtils.DeviceContext;
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
    //TODO Needs to be reimplemented... From the ground up.
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

    private final byte[] dummyDataForAttester = "Sire".getBytes();
    //private final ECPoint dummyAttesterPublicKey;

    //key value store for information concerning devices, applications and more
    private final Map<String, byte[]> storage;

    //key value store for membership state, key = appId
    private final Map<String, AppContext> membership;

    //runs and stores extensions
    private final ExtensionManager extensionManager = new ExtensionManager();

    //timeout for devices, in seconds
    private final int timeout = 30;

    private final VerifierManager verifierManager;

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
        membership = new TreeMap<>();
        storage = new TreeMap<>();
        storage.put("key", "Kamen Rider Yukito".getBytes());
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
            else if(op.toString().startsWith("ATTEST"))
                return executeOrderedAttestation(msg, messageContext);
            else if(op.toString().startsWith("MEMBERSHIP"))
                return executeOrderedMembership(msg, messageContext);
        } catch (IOException e) {
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
        switch(op) {
            case ATTEST_GENERATE_SIGNING_KEY -> {
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
            case ATTEST_GET_PUBLIC_KEY -> {
                if (verifierSigningPrivateKeyShare == null && signingKeyRequests.isEmpty()) {
                    signingKeyRequests.add(messageContext);
                    generateSigningKey();
                } else if (verifierSigningPrivateKeyShare != null){
                    return new ConfidentialMessage(verifierSigningPublicKey.getEncoded(true));
                }
            }
            case ATTEST_SIGN_DATA -> {
                lock.lock();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] data = byteStringToByteArray(out, msg.getDataToSign());
                signingData.put(messageContext.getSender(), data);
                generateRandomKey(messageContext);
                out.close();
                lock.unlock();
            }
            case ATTEST_VERIFY -> {
                DeviceEvidence deviceEvidence = new DeviceEvidence(protoToEvidence(msg.getEvidence()),
                        protoToSchnorr(msg.getSignature()));
                boolean isValidEvidence = verifierManager.verifyEvidence(deviceEvidence);
                byte[] plainData;
                if (isValidEvidence) {
                    plainData = new byte[dummyDataForAttester.length + 1];
                    plainData[0] = 1;
                    System.arraycopy(dummyDataForAttester, 0, plainData, 1,
                            dummyDataForAttester.length);
                } else {
                    plainData = new byte[] {0};
                }

                return new ConfidentialMessage(plainData);
            }
            case ATTEST_GET_RANDOM_NUMBER -> {
                lock.lock();
                VerifiableShare	share = data.get(messageContext.getSender());
                if (share == null)
                    generateRandomNumberFor(messageContext);
                else {
                    logger.debug("Sending existing random number share to {}", messageContext.getSender());
                    sendRandomNumberShareTo(messageContext, share);
                }
                lock.unlock();
            }
        }
        return null;
    }

    private ConfidentialMessage executeOrderedMembership(Messages.ProxyMessage msg, MessageContext messageContext) throws IOException {
        Messages.ProxyMessage.Operation op = msg.getOperation();
        switch(op) {
            case MEMBERSHIP_JOIN -> {
                lock.lock();
                if(!membership.containsKey(msg.getAppId()))
                    membership.put(msg.getAppId(), new AppContext(msg.getAppId(), this.timeout));

                membership.get(msg.getAppId()).addDevice(msg.getDeviceId(), new DeviceContext(msg.getDeviceId(),
                        new java.sql.Timestamp(messageContext.getTimestamp()), protoDevToDev(msg.getDeviceType())));

                extensionManager.runExtension(msg.getAppId(), ExtensionType.EXT_JOIN, msg.getDeviceId());

                lock.unlock();
                return new ConfidentialMessage();
            }
            case MEMBERSHIP_LEAVE -> {
                lock.lock();
                membership.get(msg.getAppId()).removeDevice(msg.getDeviceId());

                extensionManager.runExtension(msg.getAppId(), ExtensionType.EXT_LEAVE, msg.getDeviceId());

                lock.unlock();
                return new ConfidentialMessage();
            }
            case MEMBERSHIP_PING -> {
                lock.lock();
                membership.get(msg.getAppId()).updateDeviceTimestamp(msg.getDeviceId(),
                        new Timestamp(messageContext.getTimestamp()));

                extensionManager.runExtension(msg.getAppId(), ExtensionType.EXT_PING, msg.getDeviceId());

                lock.unlock();
                return new ConfidentialMessage();
            }
            case MEMBERSHIP_VIEW -> {
                List<DeviceContext> members = membership.get(msg.getAppId()).getMembership();
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                ObjectOutputStream out = new ObjectOutputStream(bout);
                out.writeObject(members);
                out.close();
                byte[] res = bout.toByteArray();
                bout.close();

                extensionManager.runExtension(msg.getAppId(), ExtensionType.EXT_VIEW, "");

                return new ConfidentialMessage(res);
            }
        }
        return null;
    }

    private ConfidentialMessage executeOrderedMap(Messages.ProxyMessage msg) throws IOException {
        Messages.ProxyMessage.Operation op = msg.getOperation();
        switch(op) {
            case MAP_PUT -> {
                lock.lock();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] value = byteStringToByteArray(out, msg.getValue());
                out.close();
                storage.put(msg.getKey(), value);
                extensionManager.runExtension(msg.getAppId(), ExtensionType.EXT_PUT, msg.getKey());
                lock.unlock();

                return new ConfidentialMessage();
            }
            case MAP_DELETE -> {
                lock.lock();
                storage.remove(msg.getKey());
                lock.unlock();
                extensionManager.runExtension(msg.getAppId(), ExtensionType.EXT_DEL, msg.getKey());
                return new ConfidentialMessage();
            }
            case MAP_GET -> {
                extensionManager.runExtension(msg.getAppId(), ExtensionType.EXT_GET, msg.getKey());
                return new ConfidentialMessage(storage.get(msg.getKey()));
            }
            case MAP_LIST -> {
                ArrayList<byte []> lista = new ArrayList<>(storage.values());
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                ObjectOutputStream out = new ObjectOutputStream(bout);
                out.writeObject(lista);
                out.close();
                byte[] result = bout.toByteArray();
                bout.close();

                extensionManager.runExtension(msg.getAppId(), ExtensionType.EXT_LIST, "");

                return new ConfidentialMessage(result);
            }
            case MAP_CAS -> {
                lock.lock();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                String key = msg.getKey();
                byte[] oldValue = byteStringToByteArray(out, msg.getOldData());
                byte[] newValue = byteStringToByteArray(out, msg.getValue());
                out.close();
                if(Arrays.equals(storage.get(key), oldValue)) {
                    storage.put(key, newValue);
                }
                extensionManager.runExtension(msg.getAppId(), ExtensionType.EXT_CAS, msg.getKey());
                lock.unlock();
                return new ConfidentialMessage();
            }
        }
        return null;
    }

    /**
     * Method used to generate a random number
     * @param messageContext Message context of the client requesting the generation of a random number
     */
    private void generateRandomNumberFor(MessageContext messageContext) {
        int id = distributedPolynomialManager.createRandomPolynomial(
                serviceReplica.getReplicaContext().getCurrentView().getF(),
                serviceReplica.getReplicaContext().getCurrentView().getProcesses());
        requests.put(id, messageContext);
    }

    /**
     * Method used to generate a signing key.
     */
    private void generateSigningKey() {
        signingKeyGenerationId = distributedPolynomialManager.createRandomKeyPolynomial(
                serviceReplica.getReplicaContext().getCurrentView().getF(),
                serviceReplica.getReplicaContext().getCurrentView().getProcesses());
    }

    /**
     * Method used to generate a random key used to sign data
     * @param messageContext Message context of the client requesting to sign data
     */
    private void generateRandomKey(MessageContext messageContext) {
        int id = distributedPolynomialManager.createRandomKeyPolynomial(
                serviceReplica.getReplicaContext().getCurrentView().getF(),
                serviceReplica.getReplicaContext().getCurrentView().getProcesses());
        signingRequestContexts.put(id, messageContext);
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
    public ConfidentialMessage appExecuteUnordered(byte[] bytes, VerifiableShare[] verifiableShares, MessageContext messageContext) {
        return null;
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


}
