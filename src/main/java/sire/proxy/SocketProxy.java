package sire.proxy;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import sire.attestation.DeviceEvidence;
import sire.membership.DeviceContext;
import sire.serverProxyUtils.*;

import static sire.messages.ProtoUtils.*;

import sire.messages.Messages.*;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.attestation.Evidence;
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

/**
 * @author robin
 */

public class SocketProxy implements Runnable {
	//TODO Remove responsibility of combining shares... Rethink attestation protocol asap
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
	private final Object proxyLock;

	public SocketProxy(int proxyId) throws SireException{
		this.proxyId = proxyId;

		try {
			ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
			serviceProxy = new ConfidentialServiceProxy(proxyId, responseHandler);
			proxyLock = new Object();
		} catch (SecretSharingException e) {
			throw new SireException("Failed to contact the distributed verifier", e);
		}
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
		Response response;
		try {
			ProxyMessage msg = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.ATTEST_GENERATE_SIGNING_KEY)
					.build();
			byte[] b = msg.toByteArray();
			response = serviceProxy.invokeOrdered(b);//new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
		} catch (SecretSharingException e) {
			throw new SireException("Failed to obtain verifier's public key", e);
		}
		verifierPublicKey = signatureScheme.decodePublicKey(response.getPainData());

		attesters = new HashMap<>();
	}

	@Override
	public void run() {
		try {
			ServerSocket ss = new ServerSocket(2500 + this.proxyId);
			Socket s;
			while(true) {
				s = ss.accept();
				System.out.println("New client!");
				new SireProxyThread(s).start();
				System.out.println("Connection accepted");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private class SireProxyThread extends Thread {

		private final Socket s;

		public SireProxyThread(Socket s) {
			this.s = s;
			System.out.println("Proxy Thread started!");
		}
		@Override
		public void run() {
			try {
				ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
				ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

				while (!s.isClosed()) {
					//System.out.println("Running!");
					Object o;
					while ((o = ois.readObject()) != null) {
						System.out.println("Object received! " + o);
						if (o instanceof ProxyMessage msg) {
							switch(msg.getOperation()) {
								case ATTEST_GET_VERIFIER_PUBLIC_KEY -> oos.writeObject(SchnorrSignatureScheme.encodePublicKey(verifierPublicKey));
								case MEMBERSHIP_PREJOIN -> oos.writeObject(preJoin(msg));
								case MEMBERSHIP_JOIN -> oos.writeObject(join(msg));
								default -> {
									ProxyResponse result = runProxyMessage(msg);
									if(result != null)
										oos.writeObject(result);
								}
							}
						}

					}
				}
			} catch (IOException | ClassNotFoundException | SireException | SecretSharingException e) {
				//e.printStackTrace();
				/*if (o instanceof ProtoMessage0 msg0) {
							ProtoMessage1 msg1 = joins(msg0);
							oos.writeObject(msg1);
						} else*/ /*if (o instanceof ProtoMessage2 msg2) {
							ProtoMessage3 msg3 = processMessage2(msg2);
							oos.writeObject(msg3);
						} else */
			}
		}

		private ProxyResponse runProxyMessage(ProxyMessage msg) throws IOException, SecretSharingException, ClassNotFoundException {
			Response res;
			synchronized (proxyLock) {
				res = serviceProxy.invokeOrdered(msg.toByteArray());
			}
			return switch(msg.getOperation()) {
				case MAP_GET -> mapGet(res);
				case MAP_LIST -> mapList(res);
				case MEMBERSHIP_VIEW -> memberView(res);
				case EXTENSION_GET -> extGet(res);
				case POLICY_GET -> policyGet(res);
				default -> null;
			};
		}

		private ProxyResponse policyGet(Response res) throws IOException, ClassNotFoundException {
			byte[] tmp = res.getPainData();
			if (tmp != null) {
				return ProxyResponse.newBuilder()
						.setType(ProxyResponse.ResponseType.POLICY_GET)
						.setPolicy((String) deserialize(tmp))
						.build();
			} else {
				return ProxyResponse.newBuilder().build();
			}

		}

		private ProxyResponse extGet(Response res) throws IOException, ClassNotFoundException {
			byte[] tmp = res.getPainData();
			if (tmp != null) {
				return ProxyResponse.newBuilder()
						.setType(ProxyResponse.ResponseType.EXTENSION_GET)
						.setExtension((String) deserialize(tmp))
						.build();
			} else {
				return ProxyResponse.newBuilder().build();
			}
		}

		private ProxyResponse memberView(Response res) throws IOException, ClassNotFoundException {
			byte[] tmp = res.getPainData();
			ProxyResponse.Builder prBuilder = ProxyResponse.newBuilder();
			if (tmp != null) {
				ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
				ObjectInputStream oin = new ObjectInputStream(bin);
				List<DeviceContext> members = (List<DeviceContext>) oin.readObject();
				for (DeviceContext d : members)
					if(d.isAttested()) {
						prBuilder.addMembers(ProxyResponse.ProtoDeviceContext.newBuilder()
								.setDeviceId(d.getDeviceId())
								.setTime(Timestamp.newBuilder()
										.setSeconds(d.getLastPing().getTime() / 1000)
										.build())
								.setCertificate(ByteString.copyFrom(d.getCertificate()))
								.setCertExpTime(Timestamp.newBuilder()
										.setSeconds(d.getCertExpTime().getTime() / 1000)
										.build())
								.build());
					} else {
						prBuilder.addMembers(ProxyResponse.ProtoDeviceContext.newBuilder()
								.setDeviceId(d.getDeviceId())
								.setTime(Timestamp.newBuilder()
										.setSeconds(d.getLastPing().getTime() / 1000)
										.build())
								.build());
					}

			}
			return prBuilder.build();
		}

		private ProxyResponse mapList(Response res) throws IOException, ClassNotFoundException {
			byte[] tmp = res.getPainData();
			ProxyResponse.Builder prBuilder = ProxyResponse.newBuilder();
			if (tmp != null) {
				ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
				ObjectInputStream oin = new ObjectInputStream(bin);
				ArrayList<byte[]> lst = (ArrayList<byte[]>) oin.readObject();
				for (byte[] b : lst)
					prBuilder.addList(ByteString.copyFrom(b));
			}
			return prBuilder.build();
		}

		private ProxyResponse mapGet(Response res) {
			byte[] tmp = res.getPainData();
			if (tmp != null) {
				return ProxyResponse.newBuilder()
						.setValue(ByteString.copyFrom(tmp))
						.build();
			} else {
				return ProxyResponse.newBuilder().build();
			}
		}

		private ProxyResponse preJoin(ProxyMessage msg) throws SireException {
			try {
				synchronized (proxyLock) {
					serviceProxy.invokeOrdered(msg.toByteArray());
				}
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				ECPoint attesterSessionPublicKey = signatureScheme.decodePublicKey(byteStringToByteArray(out, msg.getPubSesKey()));
				BigInteger mySessionPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
				ECPoint mySessionPublicKey = curveGenerator.multiply(mySessionPrivateKey);
				ECPoint sharedPoint = attesterSessionPublicKey.multiply(mySessionPrivateKey);
				BigInteger sharedSecret = sharedPoint.normalize().getXCoord().toBigInteger(); //TODO have to use key derivation algorithm

				byte[] sessionPublicKeysHash = computeHash(mySessionPublicKey.getEncoded(true),
						attesterSessionPublicKey.getEncoded(true));

				SecretKey symmetricEncryptionKey = createSecretKey(sharedSecret.toString().toCharArray(), sessionPublicKeysHash);
				byte[] macKey = symmetricEncryptionKey.getEncoded();

				SchnorrSignature signature = getSignatureFromVerifier(sessionPublicKeysHash);
				ProtoSchnorr protoSign = schnorrToProto(signature);


				byte[] mac = computeMac(macKey, mySessionPublicKey.getEncoded(true),
						verifierPublicKey.getEncoded(true), signature.getRandomPublicKey(),
						signature.getSigningPublicKey(), signature.getSigma());

				AttesterContext newAttester = new AttesterContext(msg.getDeviceId(), mySessionPrivateKey,
						mySessionPublicKey,
						attesterSessionPublicKey, symmetricEncryptionKey, macKey);
				attesters.put(newAttester.getAttesterId(), newAttester);

				/*ProtoMessage1 msg1 = ProtoMessage1.newBuilder()
						.setVerifierPubSesKey(ByteString.copyFrom(mySessionPublicKey.getEncoded(true)))
						.setVerifierPubKey(ByteString.copyFrom(verifierPublicKey.getEncoded(true)))
						.setSignatureSessionKeys(protoSign)
						.setMac(ByteString.copyFrom(mac))
						.build();*/

				ProxyResponse res = ProxyResponse.newBuilder()
						.setType(ProxyResponse.ResponseType.PREJOIN)
						.setVerifierPubSesKey(ByteString.copyFrom(mySessionPublicKey.getEncoded(true)))
						.setVerifierPubKey(ByteString.copyFrom(verifierPublicKey.getEncoded(true)))
						.setSignatureSessionKeys(protoSign)
						.setMac(ByteString.copyFrom(mac))
						.build();

				out.close();

				return res;
			} catch (InvalidKeySpecException | IOException | SecretSharingException e) {
				throw new SireException("Failed to create shared key", e);
			}
		}
		private ProxyResponse join(ProxyMessage msg) throws SireException, IOException {
			AttesterContext attester = attesters.get(msg.getDeviceId());
			if (attester == null)
				throw new SireException("Unknown attester id " + msg.getDeviceId());

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			ECPoint attesterSessionPublicKey = signatureScheme.decodePublicKey(byteStringToByteArray(out, msg.getPubSesKey()));
			Evidence evidence = protoToEvidence(msg.getEvidence());
			byte[] encodedAttestationServicePublicKey = evidence.getPubKey();
			boolean isValidMac = verifyMac(
					attester.getMacKey(),
					byteStringToByteArray(out, msg.getMac()),
					byteStringToByteArray(out, msg.getPubSesKey()),
					evidence.getAnchor(),
					encodedAttestationServicePublicKey,
					evidence.getVersion().getBytes(),
					evidence.getClaim()
			);

			if (!isValidMac)
				throw new SireException("Attester " + msg.getDeviceId() + "'s mac is invalid");
			if (!attester.getAttesterSessionPublicKey().equals(attesterSessionPublicKey))
				throw new SireException("Attester " + msg.getDeviceId() + "'s session public key is different");

			byte[] localAnchor = computeHash(attester.getAttesterSessionPublicKey().getEncoded(true),
					attester.getMySessionPublicKey().getEncoded(true));
			if (!Arrays.equals(localAnchor, evidence.getAnchor()))
				throw new SireException("Anchor is different");

			DeviceEvidence deviceEvidence = new DeviceEvidence(evidence, protoToSchnorr(msg.getSignature()));

			ProxyMessage dataRequest = ProxyMessage.newBuilder()
					.setDeviceId(msg.getDeviceId())
					.setAppId(msg.getAppId())
					.setOperation(ProxyMessage.Operation.MEMBERSHIP_JOIN)
					.setEvidence(evidenceToProto(deviceEvidence.getEvidence()))
					.setSignature(schnorrToProto(deviceEvidence.getEvidenceSignature()))
					.build();

			try {
				Response dataResponse;
				synchronized (proxyLock) {
					dataResponse = serviceProxy.invokeOrdered(dataRequest.toByteArray());
				}
				byte isValid = dataResponse.getPainData()[0];
				if (isValid == 0)
					throw new SireException("Evidence is invalid");
				byte[] data = new byte[dataResponse.getPainData().length - 1];
				System.arraycopy(dataResponse.getPainData(), 1, data, 0, data.length);
				byte[] encryptedData = encryptData(attester.getSymmetricEncryptionKey(), data);
				byte[] initializationVector = symmetricCipher.getIV();

				return ProxyResponse.newBuilder()
						.setType(ProxyResponse.ResponseType.JOIN)
						.setIv(ByteString.copyFrom(initializationVector))
						.setEncryptedData(ByteString.copyFrom(encryptedData))
						.build();


						/*ProtoMessage3.newBuilder()
						.setIv(ByteString.copyFrom(initializationVector))
						.setEncryptedData(ByteString.copyFrom(encryptedData))
						.build();*/

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

			ProxyMessage signingRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.ATTEST_SIGN_DATA)
					.setDataToSign(ByteString.copyFrom(data))
					.build();
			UncombinedConfidentialResponse signatureResponse;
			try {
				synchronized (proxyLock) {
					signatureResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrdered2(signingRequest.toByteArray());
				}
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

		private void close() {
			synchronized (proxyLock) {
				serviceProxy.close();
			}
		}

		/*private ProtoMessage1 joins(ProtoMessage0 msg) {
			try {
				ProxyMessage joinRequest = ProxyMessage.newBuilder()
						.setOperation(ProxyMessage.Operation.MEMBERSHIP_JOIN)
						.setAppId(msg.getAppId())
						.setDeviceId(msg.getAttesterId())
						.setDeviceType(msg.getType())
						.build();
				synchronized (proxyLock) {
					serviceProxy.invokeOrdered(joinRequest.toByteArray());
				}

				return processMessage0(msg);
			} catch (SecretSharingException | SireException e) {
				e.printStackTrace();
			}
			return null;
		}*/
	}
}
