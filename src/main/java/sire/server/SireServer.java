package sire.server;

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
import sire.DeviceEvidence;
import sire.Operation;
import sire.proxy.Evidence;
import sire.proxy.SireException;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.commitment.linear.LinearCommitments;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author robin
 */
public class SireServer implements ConfidentialSingleExecutable, RandomPolynomialListener, RandomKeyPolynomialListener {
	private final Logger logger = LoggerFactory.getLogger("sire");
	private final ServerCommunicationSystem serverCommunicationSystem;
	private final DistributedPolynomialManager distributedPolynomialManager;
	private final ServiceReplica serviceReplica;
	private final ConfidentialRecoverable cr;
	private final MessageDigest messageDigest;

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
	private final ECPoint dummyAttesterPublicKey;

	public static void main(String[] args) throws NoSuchAlgorithmException {
		if (args.length < 1) {
			System.out.println("Usage: sire.server.SireServer <server id>");
			System.exit(-1);
		}
		new SireServer(Integer.parseInt(args[0]));
	}

	public SireServer(int id) throws NoSuchAlgorithmException {
		this.id = id;
		lock = new ReentrantLock(true);
		messageDigest = MessageDigest.getInstance("SHA256");
		requests = new TreeMap<>();
		data = new TreeMap<>();
		signingKeyRequests = new LinkedList<>();
		signingRequestContexts = new TreeMap<>();
		signingData = new TreeMap<>();
		cr = new ConfidentialRecoverable(id, this);
		serviceReplica = new ServiceReplica(id, cr, cr, null, null, null, null, cr);
		serverCommunicationSystem = serviceReplica.getServerCommunicationSystem();
		distributedPolynomialManager = cr.getDistributedPolynomialManager();
		distributedPolynomialManager.setRandomPolynomialListener(this);
		distributedPolynomialManager.setRandomKeyPolynomialListener(this);
		schnorrSignatureScheme = new SchnorrSignatureScheme();
		dummyAttesterPublicKey = schnorrSignatureScheme.decodePublicKey(new byte[] {3, -27, -103, 52, -58, -46, 91, -103, -14, 0, 65, 73, -91, 31, -42, -97, 77, 19, -55, 8, 125, -9, -82, -117, -70, 102, -110, 88, -121, -76, -88, 44, -75});
	}

	@Override
	public ConfidentialMessage appExecuteOrdered(byte[] bytes, VerifiableShare[] verifiableShares,
												 MessageContext messageContext) {
		Operation op = Operation.getOperation(bytes[0]);
		logger.info("Received a {} request from {} in cid {}", op, messageContext.getSender(),
				messageContext.getConsensusId());
		switch (op) {
			case GENERATE_SIGNING_KEY -> {
				try {
					lock.lock();
					if (verifierSigningPrivateKeyShare == null && signingKeyRequests.isEmpty()) {
						signingKeyRequests.add(messageContext);
						generateSigningKey();
					} else if (verifierSigningPrivateKeyShare != null) {
						logger.warn("I already have a signing key.");
						return new ConfidentialMessage(verifierSigningPublicKey.getEncoded(true));
					} else {
						logger.warn("Signing key is being created.");
					}
				} finally {
					lock.unlock();
				}
			}
			case GET_PUBLIC_KEY -> {
				try {
					lock.lock();
					if (verifierSigningPrivateKeyShare == null && signingKeyRequests.isEmpty()) {
						signingKeyRequests.add(messageContext);
						generateSigningKey();
					} else if (verifierSigningPrivateKeyShare != null){
						return new ConfidentialMessage(verifierSigningPublicKey.getEncoded(true));
					}
				} finally {
					lock.unlock();
				}
			}
			case SIGN_DATA -> {
				lock.lock();
				byte[] data = Arrays.copyOfRange(bytes, 1, bytes.length);
				signingData.put(messageContext.getSender(), data);
				generateRandomKey(messageContext);
				lock.unlock();
			}
			case GET_RANDOM_NUMBER -> {
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
			case GET_DATA -> {
				byte[] requestData = new byte[bytes.length - 1];
				System.arraycopy(bytes, 1, requestData, 0, requestData.length);
				try {
					DeviceEvidence deviceEvidence = DeviceEvidence.deserialize(requestData);
					boolean isValidEvidence = isValidDeviceEvidence(deviceEvidence);
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
				} catch (SireException e) {
					e.printStackTrace();
				}

			}
		}
		return null;
	}

	private boolean isValidDeviceEvidence(DeviceEvidence deviceEvidence) {
		Evidence evidence = deviceEvidence.getEvidence();
		ECPoint attesterPublicKey = schnorrSignatureScheme.decodePublicKey(evidence
				.getEncodedAttestationServicePublicKey());
		if (!attesterPublicKey.equals(dummyAttesterPublicKey)) {
			return false;
		}

		byte[] signingHash = computeHash(
				evidence.getAnchor(),
				attesterPublicKey.getEncoded(true),
				evidence.getWaTZVersion().getBytes(),
				evidence.getClaim()
		);
		SchnorrSignature evidenceSignature = deviceEvidence.getEvidenceSignature();
		boolean isValidSignature = schnorrSignatureScheme.verifySignature(
				signingHash,
				attesterPublicKey,
				schnorrSignatureScheme.decodePublicKey(evidenceSignature.getRandomPublicKey()),
				new BigInteger(evidenceSignature.getSigma())
		);
		if (!isValidSignature)
			return false;

		return isValidEvidence(evidence);
	}

	private boolean isValidEvidence(Evidence evidence) {
		return true;
	}

	private byte[] computeHash(byte[]... contents) {
		for (byte[] content : contents) {
			messageDigest.update(content);
		}
		return messageDigest.digest();
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
		logger.debug("Received random number polynomial with id {} in {} ms", context.getId(), delta);
		MessageContext messageContext = requests.remove(context.getId());
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
			logger.warn("Received an unknown polynomial id {}", id);
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
		onRandomKey(context.getId(), privateKeyShare, publicKey);
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
