package sire.proxy;

import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import sire.DeviceEvidence;
import sire.Operation;
import sire.client.ServersResponseHandlerWithoutCombine;
import sire.client.UncombinedConfidentialResponse;
import sire.messages.Message0;
import sire.messages.Message1;
import sire.messages.Message2;
import sire.messages.Message3;
import protos.Messages.*;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author robin
 */
public class SireProxy {
	private static final int AES_KEY_LENGTH = 128;
	private final ConfidentialServiceProxy serviceProxy;
	private final MessageDigest messageDigest;
	private final ECPoint verifierPublicKey;
	private final SchnorrSignatureScheme signatureScheme;
	private final Map<Integer, AttesterContext> attesters;
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
			response = serviceProxy.invokeOrdered(new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
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
	public ProtoMessage1 processMessage0(ProtoMessage0 msg0) {
		try {
			ECPoint attesterSessionPublicKey = signatureScheme.decodePublicKey(message.getEncodedAttesterSessionPublicKey());
			BigInteger mySessionPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
			ECPoint mySessionPublicKey = curveGenerator.multiply(mySessionPrivateKey);
			ECPoint sharedPoint = attesterSessionPublicKey.multiply(mySessionPrivateKey);
			BigInteger sharedSecret = sharedPoint.normalize().getXCoord().toBigInteger(); //TODO have to use key derivation algorithm

			byte[] sessionPublicKeysHash = computeHash(mySessionPublicKey.getEncoded(true),
					attesterSessionPublicKey.getEncoded(true));

			SecretKey symmetricEncryptionKey = createSecretKey(sharedSecret.toString().toCharArray(), sessionPublicKeysHash);
			byte[] macKey = symmetricEncryptionKey.getEncoded();//sharedSecret.toByteArray();

			SchnorrSignature signature = getSignatureFromVerifier(sessionPublicKeysHash);


			byte[] mac = computeMac(macKey, mySessionPublicKey.getEncoded(true),
					verifierPublicKey.getEncoded(true), signature.getRandomPublicKey(),
					signature.getSigningPublicKey(), signature.getSigma());

			AttesterContext newAttester = new AttesterContext(attesterId, mySessionPrivateKey,
					mySessionPublicKey,
					attesterSessionPublicKey, symmetricEncryptionKey, macKey);
			attesters.put(newAttester.getAttesterId(), newAttester);

			return new Message1(mySessionPublicKey.getEncoded(true),
					verifierPublicKey.getEncoded(true), signature, mac);
		} catch (InvalidKeySpecException e) {
			throw new SireException("Failed to create shared key", e);
		}
	}

	public Message3 processMessage2(int attesterId, Message2 message) throws SireException {
		AttesterContext attester = attesters.get(attesterId);
		if (attester == null)
			throw new SireException("Unknown attester id " + attesterId);

		ECPoint attesterSessionPublicKey = signatureScheme.decodePublicKey(message.getEncodedAttesterSessionPublicKey());
		Evidence evidence = message.getEvidence();
		byte[] encodedAttestationServicePublicKey = evidence.getEncodedAttestationServicePublicKey();
		boolean isValidMac = verifyMac(
				attester.getMacKey(),
				message.getMac(),
				message.getEncodedAttesterSessionPublicKey(),
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

		DeviceEvidence deviceEvidence = new DeviceEvidence(evidence, message.getEvidenceSignature());

		//asking for data - verifier will return data if evidence is valid
		byte[] serializedDeviceEvidence = deviceEvidence.serialize();
		byte[] dataRequest = new byte[serializedDeviceEvidence.length + 1];
		dataRequest[0] = (byte) Operation.GET_DATA.ordinal();
		System.arraycopy(serializedDeviceEvidence, 0, dataRequest, 1,
				serializedDeviceEvidence.length);

		try {
			Response dataResponse = serviceProxy.invokeOrdered(dataRequest);
			byte isValid = dataResponse.getPainData()[0];
			if (isValid == 0)
				throw new SireException("Evidence is invalid");
			byte[] data = new byte[dataResponse.getPainData().length - 1];
			System.arraycopy(dataResponse.getPainData(), 1, data, 0, data.length);
			byte[] encryptedData = encryptData(attester.getSymmetricEncryptionKey(), data);
			byte[] initializationVector = symmetricCipher.getIV();

			return new Message3(initializationVector, encryptedData);
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

	private byte[] computeMac(byte[] secretKey, byte[]... contents) {
		macEngine.init(new KeyParameter(secretKey));
		for (byte[] content : contents) {
			macEngine.update(content, 0, content.length);
		}
		byte[] mac = new byte[macEngine.getMacSize()];
		macEngine.doFinal(mac, 0);
		return mac;
	}

	private boolean verifyMac(byte[] secretKey, byte[] mac, byte[]... contents) {
		return Arrays.equals(computeMac(secretKey, contents), mac);
	}

	private SchnorrSignature getSignatureFromVerifier(byte[] data) throws SireException {
		byte[] signingRequest = new byte[data.length + 1];
		signingRequest[0] = (byte) Operation.SIGN_DATA.ordinal();
		System.arraycopy(data, 0, signingRequest, 1, data.length);
		UncombinedConfidentialResponse signatureResponse;
		try {
			signatureResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrdered2(signingRequest);
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
}
