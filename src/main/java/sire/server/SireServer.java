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
import sire.attestation.DeviceEvidence;
import sire.attestation.PolicyManager;
import sire.attestation.VerifierManager;
import sire.coordination.CoordinationManager;
import sire.coordination.ExtensionManager;
import sire.membership.DeviceContext;
import sire.membership.MembershipManager;
import sire.messages.Messages.*;
import sire.schnorr.*;
import sire.serverProxyUtils.SireException;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.commitment.linear.LinearCommitments;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static sire.messages.ProtoUtils.*;

/**
 * @author robin
 */
public class SireServer implements ConfidentialSingleExecutable, RandomPolynomialListener, RandomKeyPolynomialListener {
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
	private SchnorrKeyPair verifierSigningKeyPair;
	//private VerifiableShare verifierSigningPrivateKeyShare;
	//private ECPoint verifierSigningPublicKey;

	//private final ECPoint dummyAttesterPublicKey;

	//key value store for information concerning devices, applications and more
	//private final Map<String, byte[]> storage;
	private final CoordinationManager storage;

	//key value store for membership state, key = appId
	//private final Map<String, AppContext> membership;
	private final MembershipManager membership;

	//runs and stores extensions
	private final ExtensionManager extensionManager = ExtensionManager.getInstance();

	//verifies the evidence
	private final VerifierManager verifierManager;
	private static PolicyManager policyManager;

	private final int timebound = 500; //in milliseconds
	private final Map<String, Timestamp> devicesTimestamps;

	private final SchnorrNonceManager schnorrNonceManager;

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
		policyManager = PolicyManager.getInstance();
		serverCommunicationSystem = serviceReplica.getServerCommunicationSystem();
		distributedPolynomialManager = cr.getDistributedPolynomialManager();
		distributedPolynomialManager.setRandomPolynomialListener(this);
		distributedPolynomialManager.setRandomKeyPolynomialListener(this);
		schnorrSignatureScheme = new SchnorrSignatureScheme();
		devicesTimestamps = new TreeMap<>();
		schnorrNonceManager = new SchnorrNonceManager(id, serviceReplica.getReplicaContext().getCurrentView().getF(),
				schnorrSignatureScheme.getCurve());
	}

	@Override
	public ConfidentialMessage appExecuteOrdered(byte[] bytes, VerifiableShare[] verifiableShares,
												 MessageContext messageContext) {
		try {
			ProxyMessage msg = ProxyMessage.parseFrom(bytes);
			ProxyMessage.Operation op = msg.getOperation();
			if(membership.containsApp(msg.getAppId()) && membership.hasDevice(msg.getAppId(), msg.getDeviceId()))
				membership.ping(msg.getAppId(), msg.getDeviceId(), new Timestamp(messageContext.getTimestamp()));
			if(op.toString().startsWith("MAP"))
				return executeOrderedMap(msg);
			else if(op.toString().startsWith("EXTENSION"))
				return executeOrderedManagement(msg);
			else if(op.toString().startsWith("POLICY"))
				return executeOrderedPolicy(msg);
			else if(op.toString().startsWith("MEMBERSHIP"))
				return executeOrderedMembership(msg, messageContext);
			else if(op.toString().startsWith("ATTEST"))
				return executeOrderedAttestation(msg, messageContext);
			else if(op.toString().startsWith("TIMESTAMP"))
				return executeOrderedTimestamp(msg, messageContext);//new ConfidentialMessage(generateTimestamp(msg, messageContext).toByteArray());
		} catch (IOException | SireException e) {
			e.printStackTrace();
		}
		return null;
	}

	private ConfidentialMessage executeOrderedTimestamp(ProxyMessage msg, MessageContext messageContext) throws IOException, SireException {
		ProxyMessage.Operation op = msg.getOperation();
		Timestamp ts = new Timestamp(messageContext.getTimestamp());
		ProxyResponse response;
		switch(op) {
			case TIMESTAMP_GET:
				if(membership.isDeviceValid(msg.getAppId(), msg.getDeviceId()))
					return new ConfidentialMessage(serialize(ts));
			default: return null;
		}
	}

	private byte[] concat(byte[]...content) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for(byte[] b : content) {
			baos.write(b);
		}
		return baos.toByteArray();
	}

	private ConfidentialMessage executeOrderedAttestation(ProxyMessage msg, MessageContext messageContext) throws IOException, SireException {
		ProxyMessage.Operation op = msg.getOperation();
		switch(op) {
			case ATTEST_GET_PUBLIC_KEY:
				try {
					lock.lock();
					if (verifierSigningKeyPair == null && signingKeyRequests.isEmpty()) {
						signingKeyRequests.add(messageContext);
						generateSigningKey();
					} else if (verifierSigningKeyPair != null) {
						logger.warn("I already have a signing key.");
						System.out.println("Signing key already created...");
						return new ConfidentialMessage(verifierSigningKeyPair.getPublicKeyShare().getEncoded(true));
					} else {
						logger.warn("Signing key is being created.");
					}
				} finally {
					lock.unlock();
				}
				break;
			case ATTEST_TIMESTAMP:
				System.out.println("Received attest timestamp request from device with id " + msg.getDeviceId());
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				Timestamp ts = new Timestamp(messageContext.getTimestamp());
				SchnorrSignature sign = protoToSchnorr(msg.getSignature());
				boolean isValid = true; /*schnorrSignatureScheme.verifySignature(computeHash(byteStringToByteArray(baos, msg.getPubKey())),
						schnorrSignatureScheme.decodePublicKey(byteStringToByteArray(baos, msg.getPubKey())),
						schnorrSignatureScheme.decodePublicKey(sign.getRandomPublicKey()), new BigInteger(sign.getSigma()));*/
				if(isValid) {
					byte[] tis = serialize(ts);
					byte[] pubKey = byteStringToByteArray(baos, msg.getPubKey());
					byte[] data = concat(tis, pubKey);
					devicesTimestamps.put(msg.getDeviceId(), ts);
					return sign(data, messageContext);//new ConfidentialMessage();
				} else {
					throw new SireException("Invalid signature!");
				}
			default: return null;
		}
		return null;
	}

	private ConfidentialMessage executeOrderedMembership(ProxyMessage msg, MessageContext messageContext) throws IOException, SireException {
		ProxyMessage.Operation op = msg.getOperation();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		if(op != ProxyMessage.Operation.MEMBERSHIP_JOIN && membership.isDeviceValid(msg.getAppId(), msg.getDeviceId()))
			throw new SireException("Unknown Device: Not attested or not in this app membership.");
		switch(op) {
			case MEMBERSHIP_JOIN:
				DeviceEvidence deviceEvidence = new DeviceEvidence(protoToEvidence(msg.getEvidence()),
						protoToSchnorr(msg.getSignature()));
				boolean isValidEvidence = verifierManager.verifyEvidence(msg.getAppId(), deviceEvidence,
						byteStringToByteArray(baos, msg.getTimestamp()));
				boolean isntTimedout = true;/*(new Timestamp(messageContext.getTimestamp())).before(
						new Timestamp(devicesTimestamps.get(msg.getDeviceId()).getTime() + timebound));*/

				if (isValidEvidence && isntTimedout) {
					byte[] data = concat(serialize(new Timestamp(messageContext.getTimestamp())),
							byteStringToByteArray(new ByteArrayOutputStream(), msg.getPubKey()), computeHash(msg.toByteArray()));
					membership.join(msg.getAppId(), msg.getDeviceId(), new Timestamp(messageContext.getTimestamp()));
					System.out.println("Device with id " + msg.getDeviceId() + " attested at " + new Timestamp(messageContext.getTimestamp()));

					return sign(data, messageContext);
				} else {
					return new ConfidentialMessage(new byte[]{0});
				}
			case MEMBERSHIP_LEAVE:
				lock.lock();
				membership.leave(msg.getAppId(), msg.getDeviceId());

				lock.unlock();
				return new ConfidentialMessage();
			case MEMBERSHIP_PING:
				lock.lock();
				membership.ping(msg.getAppId(), msg.getDeviceId(),
						new Timestamp(messageContext.getTimestamp()));

				lock.unlock();
				return new ConfidentialMessage();
			case MEMBERSHIP_VIEW:
				List<DeviceContext> members = membership.getView(msg.getAppId());
				ByteArrayOutputStream bout = new ByteArrayOutputStream();
				ObjectOutputStream out = new ObjectOutputStream(bout);
				out.writeObject(members);
				out.close();
				byte[] res = bout.toByteArray();
				bout.close();

				return new ConfidentialMessage(res);
			default: return null;
		}
	}

	private ConfidentialMessage executeOrderedManagement(ProxyMessage msg) throws IOException {
		ProxyMessage.Operation op = msg.getOperation();
		switch(op) {
			case EXTENSION_ADD:
				lock.lock();
				extensionManager.addExtension(msg.getKey(), msg.getCode());
				lock.unlock();
				return new ConfidentialMessage();
			case EXTENSION_REMOVE:
				lock.lock();
				extensionManager.removeExtension(msg.getKey());
				lock.unlock();
				return new ConfidentialMessage();
			case EXTENSION_GET:
				String code = extensionManager.getExtensionCode(msg.getKey());
				return new ConfidentialMessage(serialize(code != null ? code : "NOT FOUND"));
			default: return null;
		}
	}

	private ConfidentialMessage executeOrderedPolicy(ProxyMessage msg) throws IOException {
		ProxyMessage.Operation op = msg.getOperation();
		switch(op) {
			case POLICY_ADD:
				lock.lock();
				policyManager.setPolicy(msg.getAppId(), msg.getPolicy().getPolicy(), msg.getPolicy().getType());
				lock.unlock();
				return new ConfidentialMessage();
			case POLICY_REMOVE:
				if (!membership.containsApp(msg.getAppId()))
					return new ConfidentialMessage(serialize("NOT FOUND"));
				lock.lock();
				policyManager.removePolicy(msg.getAppId());
				lock.unlock();
				return new ConfidentialMessage();
			case POLICY_GET:
				if (!membership.containsApp(msg.getAppId()))
					return new ConfidentialMessage(serialize("NOT FOUND"));
				else
					return new ConfidentialMessage(serialize(policyManager.getPolicy(msg.getAppId())));
			default: return null;
		}
	}

	private ConfidentialMessage executeOrderedMap(ProxyMessage msg) throws IOException, SireException {
		if(membership.isDeviceValid(msg.getAppId(), msg.getDeviceId())) {
			throw new SireException("Unknown Device: Not attested or not in this app membership.");
		}
		ByteArrayOutputStream out;
		ProxyMessage.Operation op = msg.getOperation();
		switch(op) {
			case MAP_PUT:
				lock.lock();
				out = new ByteArrayOutputStream();
				byte[] value = byteStringToByteArray(out, msg.getValue());
				out.close();
				storage.put(msg.getAppId(), msg.getKey(), value);
				lock.unlock();

				return new ConfidentialMessage();
			case MAP_DELETE:
				lock.lock();
				storage.remove(msg.getAppId(), msg.getKey());
				lock.unlock();
				return new ConfidentialMessage();
			case MAP_GET:
				return new ConfidentialMessage(storage.get(msg.getAppId(), msg.getKey()));
			case MAP_LIST:
				List<byte []> lista = new ArrayList<>(storage.getValues(msg.getAppId()));
				ByteArrayOutputStream bout = new ByteArrayOutputStream();
				ObjectOutputStream oout = new ObjectOutputStream(bout);
				oout.writeObject(lista);
				oout.close();
				byte[] result = bout.toByteArray();
				bout.close();

				return new ConfidentialMessage(result);
			case MAP_CAS:
				lock.lock();
				out = new ByteArrayOutputStream();
				String key = msg.getKey();
				byte[] oldValue = byteStringToByteArray(out, msg.getOldData());
				byte[] newValue = byteStringToByteArray(out, msg.getValue());
				out.close();
				storage.cas(msg.getAppId(), key, oldValue, newValue);
				lock.unlock();
				return new ConfidentialMessage();
			default: return null;
		}
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
			signAndSend(messageContext, signingData.remove(messageContext.getSender()));
		} else if (signingKeyGenerationId == id) {
			logger.info("Received service signing key");
			verifierSigningKeyPair = new SchnorrKeyPair(privateKeyShare, publicKey);
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

	private void signAndSend(MessageContext receiverContext, byte[] data) {
		ConfidentialMessage response = sign(data, receiverContext);
		sendResponseTo(receiverContext, response);
	}

	private ConfidentialMessage sign(byte[] data, MessageContext messageContext) {
		VerifiableShare verifierSigningPrivateKeyShare = verifierSigningKeyPair.getPrivateKeyShare();
		SchnorrKeyPair nonceKeyPair = schnorrNonceManager.getNonce(String.valueOf(messageContext.getConsensusId()).getBytes());
		VerifiableShare randomPrivateKeyShare = nonceKeyPair.getPrivateKeyShare();
		ECPoint randomPublicKey = nonceKeyPair.getPublicKeyShare();
		BigInteger sigma = schnorrSignatureScheme.computePartialSignature(data,
				verifierSigningPrivateKeyShare.getShare().getShare(), randomPrivateKeyShare.getShare().getShare(), randomPublicKey);

		byte[] plainData = null;
		PublicPartialSignature publicPartialSignature = new PublicPartialSignature(
				(EllipticCurveCommitment) verifierSigningPrivateKeyShare.getCommitments(),
				(EllipticCurveCommitment) randomPrivateKeyShare.getCommitments(), randomPublicKey);
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutput out = new ObjectOutputStream(bos)) {
			publicPartialSignature.serialize(out);


			out.flush();
			bos.flush();
			plainData = concat(bos.toByteArray(), data);
		} catch (IOException e) {
			e.printStackTrace();
		}
		BigInteger shareholder = cr.getShareholderId();
		Share s = new Share(shareholder, sigma);
		VerifiableShare partialSignature = new VerifiableShare(s, new LinearCommitments(BigInteger.ZERO), null);
		return new ConfidentialMessage(plainData, partialSignature);
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
		try {
			ProxyMessage msg = ProxyMessage.parseFrom(bytes);
			ProxyMessage.Operation op = msg.getOperation();
			if(membership.containsApp(msg.getAppId()) && membership.hasDevice(msg.getAppId(), msg.getDeviceId()))
				membership.ping(msg.getAppId(), msg.getDeviceId(), new Timestamp(messageContext.getTimestamp()));
			if(op.toString().startsWith("MAP"))
				return executeOrderedMap(msg);
			else if(op.toString().startsWith("EXTENSION"))
				return executeOrderedManagement(msg);
			else if(op.toString().startsWith("POLICY"))
				return executeOrderedPolicy(msg);
			else if(op.toString().startsWith("MEMBERSHIP"))
				return executeOrderedMembership(msg, messageContext);
			else if(op.toString().startsWith("ATTEST"))
				return executeOrderedAttestation(msg, messageContext);
			else if(op.toString().startsWith("TIMESTAMP"))
				return executeOrderedTimestamp(msg, messageContext);
		} catch (IOException | SireException e) {
			e.printStackTrace();
		}
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
}
