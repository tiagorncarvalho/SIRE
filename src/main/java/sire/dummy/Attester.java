package sire.dummy;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import sire.messages.Message1;
import sire.messages.Message3;
import sire.serverProxyUtils.DeviceContext;
import sire.utils.Evidence;
import sire.serverProxyUtils.SireException;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.utils.ExampleObject;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.List;

import static sire.utils.ProtoUtils.deserialize;
import static sire.utils.ProtoUtils.serialize;

/**
 * @author robin
 */
public class Attester {
	private static final int AES_KEY_LENGTH = 128;
	private static final SecureRandom rndGenerator = new SecureRandom("sire".getBytes());
	private static CMac macEngine;
	private static SecretKeyFactory secretKeyFactory;
	private static MessageDigest messageDigest;
	private static Cipher symmetricCipher;

	public static void main(String[] args) throws SireException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException, ClassNotFoundException {
		String attesterId = args[0];
		int proxyId = 1;
		String appId = "app1";
		String waTZVersion = "1.0";
		byte[] claim = "claim".getBytes();
		secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		messageDigest = MessageDigest.getInstance("SHA256");
		macEngine = new CMac(new AESEngine());
		symmetricCipher = Cipher.getInstance("AES/GCM/NoPadding");
		SchnorrSignatureScheme signatureScheme = new SchnorrSignatureScheme();
		//SireProxy proxy = new SireProxy(proxyId);
		DummyAttester dummy = new DummyAttester(proxyId);
		ECPoint verifierPublicKey = dummy.getVerifierPublicKey();
		ECPoint curveGenerator = signatureScheme.getGenerator();
		BigInteger attesterPrivateKey = new BigInteger("4049546346519992604730332816858472394381393488413156548605745581385");
		ECPoint attesterPublicKey = curveGenerator.multiply(attesterPrivateKey);

		try {

			//Generating a message0
			BigInteger attesterSessionPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
			ECPoint attesterSessionPublicKey = curveGenerator.multiply(attesterSessionPrivateKey);

			//Message0 message0 = new Message0(attesterId, attesterSessionPublicKey.getEncoded(true));

			Message1 message1 = dummy.join(appId, attesterId, attesterSessionPublicKey.getEncoded(true));

			byte[] sessionPublicKeysHash = computeHash(message1.getVerifierPublicSessionKey(),
					attesterSessionPublicKey.getEncoded(true));

			//computing shared keys
			ECPoint verifierSessionPublicKey = signatureScheme.decodePublicKey(message1.getVerifierPublicSessionKey());
			ECPoint sharedPoint = verifierSessionPublicKey.multiply(attesterSessionPrivateKey);
			BigInteger sharedSecret = sharedPoint.normalize().getXCoord().toBigInteger();
			SecretKey symmetricEncryptionKey = createSecretKey(sharedSecret.toString().toCharArray(), sessionPublicKeysHash);
			byte[] macKey = symmetricEncryptionKey.getEncoded();//sharedSecret.toByteArray();

			//checking validity of the message1
			SchnorrSignature signatureOfSessionKeys = message1.getSignatureOfSessionKeys();
			boolean isValidSessionSignature = signatureScheme.verifySignature(sessionPublicKeysHash, verifierPublicKey,
					signatureScheme.decodePublicKey(signatureOfSessionKeys.getRandomPublicKey()),
					new BigInteger(signatureOfSessionKeys.getSigma()));

			if (!isValidSessionSignature) {
				throw new IllegalStateException("Session keys signature is invalid");
			}

			System.out.println();
			boolean isValidMac = verifyMac(macKey, message1.getMac(), verifierSessionPublicKey.getEncoded(true),
					verifierPublicKey.getEncoded(true), signatureOfSessionKeys.getRandomPublicKey(),
					verifierPublicKey.getEncoded(true), signatureOfSessionKeys.getSigma());

			if (!isValidMac) {
				throw new IllegalStateException("Mac of message1 is invalid");
			}

			boolean isValidVerifierPublicKey = verifierPublicKey.equals(signatureScheme.decodePublicKey(message1.getVerifierPublicKey()));
			if (!isValidVerifierPublicKey) {
				throw new IllegalStateException("Verifier's public key is invalid");
			}

			//creating the message2
			byte[] anchor = computeHash(attesterSessionPublicKey.getEncoded(true),
					verifierSessionPublicKey.getEncoded(true));
			Evidence evidence = new Evidence(anchor, waTZVersion, claim, attesterPublicKey.getEncoded(true));

			byte[] signingHash = computeHash(
					anchor,
					attesterPublicKey.getEncoded(true),
					waTZVersion.getBytes(),
					claim
			);
			BigInteger randomPrivateKey = getRandomNumber(curveGenerator.getCurve().getOrder());
			ECPoint randomPublicKey = curveGenerator.multiply(randomPrivateKey);
			SchnorrSignature signature = signatureScheme.computeSignature(signingHash, attesterPrivateKey,
					attesterPublicKey, randomPrivateKey, randomPublicKey);

			byte[] mac = computeMac(
					macKey,
					attesterSessionPublicKey.getEncoded(true),
					anchor,
					attesterPublicKey.getEncoded(true),
					waTZVersion.getBytes(),
					claim
			);

			Message3 message3 = dummy.sendMessage2(attesterId, attesterSessionPublicKey.getEncoded(true),
					evidence, signature, mac);
			byte[] decryptedData = decryptData(symmetricEncryptionKey, message3.getInitializationVector(),
					message3.getEncryptedData());
			System.out.println("Verifier sent me: " + new String(decryptedData));

			String key = "exampleKey" + attesterId;
			String key2 = "exampleKey2" + attesterId;
			/*String value = "exampleValue";
			String value2 = "exampleValue2";
			String newValue = "exampleNewValue";*/
			ExampleObject value = new ExampleObject("exampleValue" + attesterId);
			ExampleObject value2 = new ExampleObject("exampleValue2" + attesterId);
			ExampleObject newValue = new ExampleObject("exampleNewValue" + attesterId);

			System.out.println("Putting entry: " + key + " " + value.getValue());
			dummy.put(appId, key, serialize(value));
			ExampleObject test = (ExampleObject) deserialize(serialize(value));
			System.out.println("Test: " + test.getValue());
			ExampleObject aberration = (ExampleObject) deserialize(dummy.getData(appId, key));
			System.out.println("Getting entry: " + key + " Value: " + aberration.getValue());

			System.out.println("Putting entry: " + key2 + " " + value2.getValue());
			dummy.put(appId, key2, serialize(value2));
			System.out.print("Getting all entries: [");
			List<byte[]> res = dummy.getList(appId);
			for(byte[] b : res)
				System.out.print(((ExampleObject) deserialize(b)).getValue() + ",");
			System.out.println("]");

			System.out.println("Delete entry: " + key2);
			dummy.delete(appId, key2);

			System.out.print("Getting entry: " + key2 + " Value: ");
			Object arr = dummy.getData(appId, key2);
			if(arr == null)
				System.out.println("null");
			else
				System.out.println((String) arr);

			System.out.println("Cas, key: " + key + " oldValue: " + value.getValue() + " newValue: " + newValue.getValue());
			dummy.cas(appId, key, serialize(value), serialize(newValue));

			ExampleObject result = (ExampleObject) deserialize(dummy.getData(appId, key));

			System.out.println("Getting entry: " + key + " Value: " + result.getValue());

			for(DeviceContext d : dummy.getView(appId))
				System.out.println(d.toString());
			dummy.ping(appId, attesterId);
			for(DeviceContext d : dummy.getView(appId))
				System.out.println(d.toString());
			dummy.leave(appId, attesterId);
			for(DeviceContext d : dummy.getView(appId))
				System.out.println(d.toString());
			System.out.println("Done!");

		} catch (IOException | ClassNotFoundException | InterruptedException e) {
			e.printStackTrace();
		} finally {
			dummy.close();
		}
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
		for (byte[] content : contents) {
			messageDigest.update(content);
		}
		return messageDigest.digest();
	}

	private static SecretKey createSecretKey(char[] password, byte[] salt) throws InvalidKeySpecException {
		KeySpec spec = new PBEKeySpec(password, salt, 65536, AES_KEY_LENGTH);
		return new SecretKeySpec(secretKeyFactory.generateSecret(spec).getEncoded(), "AES");
	}



	private static boolean verifyMac(byte[] secretKey, byte[] mac, byte[]... contents) {
		return Arrays.equals(computeMac(secretKey, contents), mac);
	}

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
}
