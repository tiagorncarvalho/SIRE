package sire.proxy;

import com.google.protobuf.ByteString;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import sire.DeviceEvidence;
import sire.client.ServersResponseHandlerWithoutCombine;
import sire.client.UncombinedConfidentialResponse;
import static sire.utils.ProtoUtils.*;

import sire.extensions.Extension;
import sire.extensions.ExtensionType;
import sire.api.ManagementInterface;
import sire.api.MapInterface;
import sire.api.OperationalInterface;
import sire.protos.Messages.*;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.AppContext;
import sire.serverProxyUtils.AttesterContext;
import sire.serverProxyUtils.Policy;
import sire.serverProxyUtils.SireException;
import sire.utils.Evidence;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
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
public class SireProxy implements MapInterface, OperationalInterface, ManagementInterface {
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

	public SireProxy(int proxyId) throws SireException {
		try {
			ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
			this.serviceProxy = new ConfidentialServiceProxy(proxyId, responseHandler);
		} catch (SecretSharingException e) {
			throw new SireException("Failed to contact the distributed verifier", e);
		}
		try {
			this.messageDigest = MessageDigest.getInstance("SHA256");
			BlockCipher aes = new AESEngine();

			macEngine = new CMac(aes);
			this.secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			this.signatureScheme = new SchnorrSignatureScheme();
			this.curveGenerator = signatureScheme.getGenerator();
			this.symmetricCipher = Cipher.getInstance("AES/GCM/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new SireException("Failed to initialize cryptographic tools", e);
		}
		Response response;
		try {
			ProxyMessage msg = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.GENERATE_SIGNING_KEY)
					.build();
			response = serviceProxy.invokeOrdered(msg.toByteArray());//new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
		} catch (SecretSharingException e) {
			throw new SireException("Failed to obtain verifier's public key", e);
		}
		this.verifierPublicKey = signatureScheme.decodePublicKey(response.getPainData());
		this.attesters = new HashMap<>();
	}

	public ECPoint getVerifierPublicKey() {
		return verifierPublicKey;
	}


	//public Message1 processMessage0(int attesterId, Message0 message) throws SireException {

	public ProtoMessage1 processMessage0(ProtoMessage0 msg0) throws SireException {
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
			ProtoSchnorr protoSign = schnorrToProto(signature);


			byte[] mac = computeMac(macKey, mySessionPublicKey.getEncoded(true),
					verifierPublicKey.getEncoded(true), signature.getRandomPublicKey(),
					signature.getSigningPublicKey(), signature.getSigma());

			AttesterContext newAttester = new AttesterContext(msg0.getAttesterId(), mySessionPrivateKey,
					mySessionPublicKey,
					attesterSessionPublicKey, symmetricEncryptionKey, macKey);
			attesters.put(newAttester.getAttesterId(), newAttester);

			ProtoMessage1 msg1 = ProtoMessage1.newBuilder()
					.setVerifierPubSesKey(ByteString.copyFrom(mySessionPublicKey.getEncoded(true)))
					.setVerifierPubKey(ByteString.copyFrom(verifierPublicKey.getEncoded(true)))
					.setSignatureSessionKeys(protoSign)
					.setMac(ByteString.copyFrom(mac))
					.build();

			out.close();

			return msg1;

			//return new Message1(mySessionPublicKey.getEncoded(true),
			//		verifierPublicKey.getEncoded(true), signature, mac);
		} catch (InvalidKeySpecException | IOException e) {
			throw new SireException("Failed to create shared key", e);
		}
	}

	//public Message3 processMessage2(int attesterId, Message2 message) throws SireException {
	public ProtoMessage3 processMessage2(String attesterId, ProtoMessage2 message) throws SireException, IOException {
		AttesterContext attester = attesters.get(attesterId);
		if (attester == null)
			throw new SireException("Unknown attester id " + attesterId);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ECPoint attesterSessionPublicKey = signatureScheme.decodePublicKey(byteStringToByteArray(out,message.getAttesterPubSesKey()));
		Evidence evidence = protoToEvidence(message.getEvidence());
		byte[] encodedAttestationServicePublicKey = evidence.getEncodedAttestationServicePublicKey();
		//System.out.println("Message mac " + Arrays.toString(byteStringToByteArray(out,message.getMac())));
		boolean isValidMac = verifyMac(
				attester.getMacKey(),
				byteStringToByteArray(out, message.getMac()),
				byteStringToByteArray(out, message.getAttesterPubSesKey()),
				evidence.getAnchor(),
				encodedAttestationServicePublicKey,
				evidence.getWaTZVersion().getBytes(),
				evidence.getClaim()
		);

		if (!isValidMac)
			throw new SireException("Attester " + attesterId + "'s mac is invalid");
		if (!attester.getAttesterSessionPublicKey().equals(attesterSessionPublicKey))
			throw new SireException("Attester " + attesterId + "'s session public key is different");

		byte[] localAnchor = computeHash(attester.getAttesterSessionPublicKey().getEncoded(true),
				attester.getMySessionPublicKey().getEncoded(true));
		if (!Arrays.equals(localAnchor, evidence.getAnchor()))
			throw new SireException("Anchor is different");

		DeviceEvidence deviceEvidence = new DeviceEvidence(evidence, protoToSchnorr(message.getSignatureEvidence()));

		//asking for data - verifier will return data if evidence is valid
		/*byte[] serializedDeviceEvidence = deviceEvidence.serialize();
		byte[] dataRequest = new byte[serializedDeviceEvidence.length + 1];
		dataRequest[0] = (byte) Operation.GET_DATA.ordinal();
		System.arraycopy(serializedDeviceEvidence, 0, dataRequest, 1,
				serializedDeviceEvidence.length);*/

		ProxyMessage dataRequest = ProxyMessage.newBuilder()
				.setOperation(ProxyMessage.Operation.GET_DATA)
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

			return ProtoMessage3.newBuilder()
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
		//System.out.println("Computed Mac " + Arrays.toString(computeMac(secretKey, contents)) + " message mac " + Arrays.toString(mac));
		return Arrays.equals(computeMac(secretKey, contents), mac);
	}

	private SchnorrSignature getSignatureFromVerifier(byte[] data) throws SireException {
		/*byte[] signingRequest = new byte[data.length + 1];
		signingRequest[0] = (byte) Operation.SIGN_DATA.ordinal();
		System.arraycopy(data, 0, signingRequest, 1, data.length);*/

		ProxyMessage signingRequest = ProxyMessage.newBuilder()
				.setOperation(ProxyMessage.Operation.SIGN_DATA)
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

	@Override
	public void put(String appId, String key, byte[] value) {
		/*byte[] putRequest = new byte[key.length + value.length + 2];
		putRequest[0] = (byte) Operation.MAP_PUT.ordinal();
		byte[] mark = "/".getBytes();
		System.arraycopy(key, 0, putRequest, 1, key.length);
		System.arraycopy(mark, 0, putRequest, key.length + 1, mark.length);
		System.arraycopy(value, 0, putRequest, key.length + 1, value.length);*/
		try {
			ProxyMessage putRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.MAP_PUT)
					.setKey(key)
					.setAppId(appId)
					.setValue(ByteString.copyFrom(value))
					.build();

			serviceProxy.invokeOrdered2(putRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void delete(String appId, String key) {
		/*byte[] deleteRequest = new byte[key.length + 1];
		deleteRequest[0] = (byte) Operation.MAP_DELETE.ordinal();
		System.arraycopy(key, 0, deleteRequest, 1, key.length);*/
		ProxyMessage deleteRequest = ProxyMessage.newBuilder()
				.setOperation(ProxyMessage.Operation.MAP_DELETE)
				.setKey(key)
				.setAppId(appId)
				.build();
		try {
			serviceProxy.invokeOrdered2(deleteRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public byte[] getData(String appId, String key) {
		/*byte[] getRequest = new byte[key.length + 1];
		getRequest[0] = (byte) Operation.MAP_GET.ordinal();
		System.arraycopy(key, 0, getRequest, 1, key.length);*/
		ProxyMessage getRequest = ProxyMessage.newBuilder()
				.setOperation(ProxyMessage.Operation.MAP_GET)
				.setKey(key)
				.setAppId(appId)
				.build();
		try {
			return serviceProxy.invokeOrdered(getRequest.toByteArray()).getPainData();
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public List<byte[]> getList(String appId) {
		ProxyMessage listRequest = ProxyMessage.newBuilder()
				.setOperation(ProxyMessage.Operation.MAP_LIST)
				.setAppId(appId)
				.build();
		try {
			byte[] response = serviceProxy.invokeOrdered(listRequest.toByteArray()).getPainData();
			List<byte[]> result = (ArrayList<byte[]>) deserialize(response);

			return result;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void cas(String appId, String key, byte[] oldData, byte[] newData) {
		/*byte[] casRequest = new byte[key.length + oldData.length + newData.length + 1];
		casRequest[0] = (byte) Operation.MAP_CAS.ordinal();
		byte[] mark = "/".getBytes();
		System.arraycopy(key, 0, casRequest, 1, key.length);
		System.arraycopy(mark, 0, casRequest, key.length + 1, mark.length);
		System.arraycopy(oldData, 0, casRequest, key.length + mark.length + 1, oldData.length);
		System.arraycopy(mark, 0, casRequest, key.length + mark.length + oldData.length + 1, mark.length);
		System.arraycopy(newData, 0, casRequest, key.length + (mark.length * 2) + oldData.length + 1, newData.length);*/
		try {
			ProxyMessage casRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.MAP_CAS)
					.setKey(key)
					.setOldData(ByteString.copyFrom(oldData))
					.setValue(ByteString.copyFrom(newData))
					.setAppId(appId)
					.build();
			serviceProxy.invokeOrdered(casRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public ProtoMessage1 join(String appId, String deviceId, ProtoMessage0 msg)  {
		try {
			ProxyMessage joinRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.JOIN)
					.setAppId(appId)
					.setDeviceId(deviceId)
					.build();
			serviceProxy.invokeOrdered(joinRequest.toByteArray());

			return processMessage0(msg);
		} catch (SecretSharingException | SireException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void leave(String appId, String deviceId) {
		try {
			ProxyMessage leaveRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.LEAVE)
					.setAppId(appId)
					.setDeviceId(deviceId)
					.build();
			serviceProxy.invokeOrdered(leaveRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void ping(String appId, String deviceId) {
		try {
			ProxyMessage pingRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.PING)
					.setAppId(appId)
					.setDeviceId(deviceId)
					.build();
			serviceProxy.invokeOrdered(pingRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public AppContext getView(String appId) {
		try {
			ProxyMessage leaveRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.VIEW)
					.setAppId(appId)
					.build();
			Response res = serviceProxy.invokeOrdered(leaveRequest.toByteArray());
			return (AppContext) deserialize(res.getPainData());
		} catch (SecretSharingException | IOException | ClassNotFoundException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public void addExtension(String appId, ExtensionType type, String key, String code) {
		try {
			ProxyMessage addExtRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.EXTENSION_ADD)
					.setAppId(appId)
					.setCode(code)
					.setType(extTypeToProto(type))
					.setKey(key)
					.build();
			serviceProxy.invokeOrdered(addExtRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void removeExtension(String appId, ExtensionType type, String key) {
		try {
			ProxyMessage removeExtRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.EXTENSION_REMOVE)
					.setAppId(appId)
					.setType(extTypeToProto(type))
					.setKey(key)
					.build();
			serviceProxy.invokeOrdered(removeExtRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public Extension getExtension(String appId, ExtensionType type, String key) {
		try {
			ProxyMessage getExtRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.EXTENSION_GET)
					.setAppId(appId)
					.setType(extTypeToProto(type))
					.setKey(key)
					.build();
			Response res = serviceProxy.invokeOrdered(getExtRequest.toByteArray());
			return new Extension ((String) deserialize(res.getPainData()));
		} catch (SecretSharingException | IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void setPolicy(String appId, String policy) {
		try {
			ProxyMessage addPolRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.POLICY_ADD)
					.setAppId(appId)
					.setPolicy(policy)
					.build();
			serviceProxy.invokeOrdered(addPolRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void deletePolicy(String appId) {
		try {
			ProxyMessage removePolRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.POLICY_REMOVE)
					.setAppId(appId)
					.build();
			serviceProxy.invokeOrdered(removePolRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public Policy getPolicy(String appId) {
		try {
			ProxyMessage getPolRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.POLICY_GET)
					.setAppId(appId)
					.build();
			Response res = serviceProxy.invokeOrdered(getPolRequest.toByteArray());
			return (Policy) deserialize(res.getPainData());
		} catch (SecretSharingException | IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
		return null;
	}
}
