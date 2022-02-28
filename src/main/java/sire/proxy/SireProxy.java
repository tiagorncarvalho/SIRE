package sire.proxy;

import com.google.protobuf.ByteString;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import sire.serverProxyUtils.DeviceEvidence;
import sire.utils.ProtoUtils;
import sire.utils.ServersResponseHandlerWithoutCombine;
import sire.utils.UncombinedConfidentialResponse;
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
public class SireProxy extends Thread {
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

	private Socket s;
	private ObjectOutputStream oos;
	private ObjectInputStream ois;

	public SireProxy(int proxyId, Socket s) throws SireException {
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
			byte [] b = msg.toByteArray();
			System.out.println(b);
			response = serviceProxy.invokeOrdered(b);//new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
		} catch (SecretSharingException e) {
			throw new SireException("Failed to obtain verifier's public key", e);
		}
		this.verifierPublicKey = signatureScheme.decodePublicKey(response.getPainData());
		this.attesters = new HashMap<>();
		this.s = s;
	}

	public void run() {
		try {
			oos = new ObjectOutputStream(s.getOutputStream());
			ois = new ObjectInputStream(s.getInputStream());


			while(!s.isClosed()) {
				System.out.println("Running!");
				//byte[] b = new byte[10000];
				Object o;
				//while(dis.read(b) > 0) {
				while((o = ois.readObject()) != null) {
					//System.out.println("Bytes received! " + b);
					System.out.println("Object received! " + o);
					//Object o = ProtoUtils.deserialize(b);
					if(o instanceof ProtoMessage0) {
						ProtoMessage0 msg0 = (ProtoMessage0) o;
						ProtoMessage1 msg1 = joins(msg0);
						oos.writeObject(msg1);
					}
					else if(o instanceof ProtoMessage2) {
						ProtoMessage2 msg2 = (ProtoMessage2) o;
						ProtoMessage3 msg3 = processMessage2(msg2);
						oos.writeObject(msg3);
					}
					else if(o instanceof ProxyMessage) {
						ProxyMessage msg = (ProxyMessage) o;
						if(msg.getOperation() == ProxyMessage.Operation.GET_VERIFIER_PUBLIC_KEY) {
							System.out.println("Getting key");
							oos.writeObject(SchnorrSignatureScheme.encodePublicKey(verifierPublicKey));
						}
						else {
							Response res = serviceProxy.invokeOrdered(msg.toByteArray());
							if(msg.getOperation() == ProxyMessage.Operation.MAP_GET) {
								byte[] tmp = res.getPainData();
								ProxyResponse result;
								if(tmp != null) {
									result = ProxyResponse.newBuilder()
											.setValue(ByteString.copyFrom(tmp))
											.build();
								}
								else {
									result = ProxyResponse.newBuilder().build();
								}
								oos.writeObject(result);
							}
							else if(msg.getOperation() == ProxyMessage.Operation.MAP_LIST) {
								byte[] tmp = res.getPainData();
								ProxyResponse result;
								ProxyResponse.Builder prBuilder = ProxyResponse.newBuilder();
								if(tmp != null) {
									ArrayList<byte []> lst = (ArrayList<byte[]>) deserialize(tmp);
									System.out.println("List size: " + lst.size());
									for(byte[] b : lst)
										prBuilder.addList(ByteString.copyFrom(b));
									/*for(int i = 0; i < lst.size(); i++)
										prBuilder.setList(i, ByteString.copyFrom(lst.get(i)));*/
									result = prBuilder.build();
								}
								else {
									result = prBuilder.build();
								}
								oos.writeObject(result);
							}

						}
						/*switch(msg.getOperation()) {
							case GENERATE_SIGNING_KEY -> {
							}
							case GET_PUBLIC_KEY -> {
							}
							case SIGN_DATA -> {
							}
							case GET_DATA -> {
							}
							case GET_RANDOM_NUMBER -> {
							}
							case MAP_PUT -> {
							}
							case MAP_DELETE -> {
							}
							case MAP_GET -> {
							}
							case MAP_LIST -> {
							}
							case MAP_CAS -> {
							}
							case JOIN -> {
							}
							case LEAVE -> {
							}
							case VIEW -> {
							}
							case PING -> {
							}
							case EXTENSION_ADD -> {
							}
							case EXTENSION_REMOVE -> {
							}
							case EXTENSION_GET -> {
							}
							case POLICY_ADD -> {
							}
							case POLICY_REMOVE -> {
							}
							case POLICY_GET -> {
							}
							case GET_VERIFIER_PUBLIC_KEY -> {
								System.out.println("Getting key");
								oos.writeObject(SchnorrSignatureScheme.encodePublicKey(verifierPublicKey));
							}
							case UNRECOGNIZED -> {
							}
						}*/
					}

				}
			}
		} catch (IOException | ClassNotFoundException | SireException | SecretSharingException e) {
			e.printStackTrace();
		}
	}

/*	public ECPoint getVerifierPublicKey() {
		return verifierPublicKey;
	}*/

	public ProtoMessage1 processMessage0(ProtoMessage0 msg0) throws SireException {
		System.out.println("Processing Message 0!");
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

			System.out.println("Message 0 done!");

			return msg1;
		} catch (InvalidKeySpecException | IOException e) {
			throw new SireException("Failed to create shared key", e);
		}
	}

	//public Message3 processMessage2(int attesterId, Message2 message) throws SireException {
	public ProtoMessage3 processMessage2(ProtoMessage2 msg2) throws SireException, IOException {
		AttesterContext attester = attesters.get(msg2.getAttesterId());
		if (attester == null)
			throw new SireException("Unknown attester id " + msg2.getAttesterId());

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ECPoint attesterSessionPublicKey = signatureScheme.decodePublicKey(byteStringToByteArray(out,msg2.getAttesterPubSesKey()));
		Evidence evidence = protoToEvidence(msg2.getEvidence());
		byte[] encodedAttestationServicePublicKey = evidence.getEncodedAttestationServicePublicKey();
		//System.out.println("Message mac " + Arrays.toString(byteStringToByteArray(out,message.getMac())));
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
		return Arrays.equals(computeMac(secretKey, contents), mac);
	}

	private SchnorrSignature getSignatureFromVerifier(byte[] data) throws SireException {

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

	public ProtoMessage1 joins(ProtoMessage0 msg)  {
		try {
			ProxyMessage joinRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.JOIN)
					.setAppId(msg.getAppId())
					.setDeviceId(msg.getAttesterId())
					.build();
			serviceProxy.invokeOrdered(joinRequest.toByteArray());

			return processMessage0(msg);
		} catch (SecretSharingException | SireException e) {
			e.printStackTrace();
		}
		return null;
	}

	/*public void put(String appId, String key, byte[] value) {
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

	public void delete(String appId, String key) {
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

	public byte[] getData(String appId, String key) {
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

	public void cas(String appId, String key, byte[] oldData, byte[] newData) {
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


	public void leave(ProxyMessage msg) {
		try {
			ProxyMessage leaveRequest = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.LEAVE)
					.setAppId(appId)
					.setDeviceId(deviceId)
					.build();*//*
			serviceProxy.invokeOrdered(leaveRequest.toByteArray());
		} catch (SecretSharingException e) {
			e.printStackTrace();
		}
	}

	public void ping(ProxyMessage msg) {
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

	public AppContext getView(ProxyMessage msg) {
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
	}*/
}
