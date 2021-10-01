package sire.dummy;

import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import sire.messages.*;
import vss.facade.SecretSharingException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * @author robin
 */
public class Attester {
	private static final BigInteger generator = new BigInteger("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16);
	private static final BigInteger primeField = new BigInteger("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16);
	private static final BigInteger subField = new BigInteger("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16);
	private static final SecureRandom rndGenerator = new SecureRandom("sire".getBytes());
	private static Signature signingEngine;
	private static Mac macEngine;
	private static SecretKeyFactory secretKeyFactory;
	private static MessageDigest messageDigest;

	public static void main(String[] args) throws SecretSharingException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
		BigInteger privateSessionKeyPart = getRandomNumber();
		int attesterId = 1;
		String waTZVersion = "1.0";
		byte[] claim = createHash("println(\"Hello World!\")".getBytes());//hash of the bytecode

		signingEngine = Signature.getInstance("SHA256withRSA");
		macEngine = Mac.getInstance("HmacSHA256");
		secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		messageDigest = MessageDigest.getInstance("SHA256");
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		byte[] encodedPrivateKey = {48, -126, 4, -66, 2, 1, 0, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 4, -126, 4, -88, 48, -126, 4, -92, 2, 1, 0, 2, -126, 1, 1, 0, -41, -26, 10, -62, -2, -97, 123, 113, -21, 88, -127, 93, 95, 96, 18, 44, 47, -97, -45, -125, 32, -85, -11, -123, 63, -70, -29, -95, 16, 21, 102, 60, 106, -105, -115, -90, 29, 6, 119, -54, -47, -70, 13, -94, -52, -86, 59, 61, 43, 1, 87, 69, -99, -30, -59, 102, -58, -97, 83, 22, -16, 84, 95, -114, -100, 19, 77, -77, -68, 39, 91, 95, -117, 44, 89, 105, 22, 107, -30, -77, 38, 108, 97, -34, 21, -79, 28, -12, 39, 12, 52, -101, 17, -36, -38, -60, -98, 17, 46, 79, 80, -53, -99, -123, 29, -79, -45, 119, 23, 14, -81, -35, -19, -107, 64, 89, 14, 102, 12, 113, 105, 45, 50, -100, 80, -33, -10, 93, -113, 22, 17, -75, -17, -63, 32, 36, 45, -55, 70, 33, 23, -61, 62, 49, -75, 45, 99, -83, 37, 41, -109, -32, -79, 48, 65, -76, -40, 62, -47, 25, 87, 55, -7, -37, -61, -18, -64, 120, 113, -44, 119, 75, 104, 40, -66, -93, -103, -1, -63, -3, 123, -72, 82, -15, 64, -109, 40, 64, -120, -46, 24, -116, 39, 33, 109, -56, -15, -79, -109, -67, -128, -16, 15, -24, 96, 98, -115, -93, 60, 7, -118, 76, -1, -21, 46, 37, 24, 62, -51, -9, 58, 82, -5, 83, -123, -19, 39, -84, -69, 67, 99, 69, -86, -92, 84, -59, -95, -101, 2, -81, 96, -19, -35, 53, 48, -121, 94, -27, 15, -67, 43, -46, -15, -32, 94, 105, 2, 3, 1, 0, 1, 2, -126, 1, 0, 6, -83, -111, 58, 119, -89, -84, -111, -103, 23, -85, 83, -6, 115, -88, -9, -32, 72, 83, -5, -62, 78, 45, -27, -18, 1, -85, -44, -119, -82, -81, 10, -115, -46, 10, 88, 120, 87, 117, 26, 30, 38, 84, -53, -115, -43, 45, 60, 92, -120, 56, -107, -6, 114, 119, -44, -65, 34, -36, -18, 32, -86, 73, 67, 74, -84, -128, 46, 95, -46, -65, -92, -112, 37, -99, -27, 120, -90, 30, 71, -127, 35, -99, 91, -27, 21, 60, 87, -120, -52, 100, 89, -51, -111, -57, 126, -73, -79, 123, -119, 21, -29, -114, 112, 114, -104, 48, 121, -52, 79, -45, -62, -128, -97, -110, 92, 49, -67, -81, 84, -63, 19, -106, 35, -61, -67, 48, 64, -91, 52, -4, 2, -22, -71, 45, 124, 41, -3, -99, 12, 47, -52, 73, 1, -10, 90, -122, -33, 27, 7, -2, -7, -120, 100, -103, 42, -5, 26, 124, 122, 114, -35, 96, -114, 16, 100, 70, -89, -98, -27, 33, 53, -6, -82, 72, -39, -28, -17, -54, -93, -21, -105, -28, -69, -6, 62, -115, -63, -118, 54, 115, -12, -84, -127, -55, -24, 102, 66, -26, -3, -46, 70, 92, -26, 84, -101, -64, 88, 95, 56, -2, -7, 121, -9, -72, -78, -29, 14, -58, 7, -98, 18, -10, 8, -103, 18, 20, 39, -34, 96, 56, -56, 104, 33, -59, -62, 80, 9, -10, -122, -58, 3, 59, 44, 53, -83, -37, 37, 116, 6, 87, 117, 29, 117, 79, 23, 2, -127, -127, 0, -35, -78, 81, 121, 94, 43, 39, -93, -43, 8, -36, 32, -36, -83, -34, 78, -38, -79, -87, 31, 123, -78, 18, -23, -26, 21, 13, 4, -12, 19, 21, -29, 46, 58, -22, 20, 64, 94, -44, 80, 55, -128, -2, 3, -78, 63, -76, -29, -45, -42, 3, -65, 44, -26, 10, 103, 20, 80, -67, -88, -30, -85, -15, 26, -20, 99, -35, 36, 63, 110, -45, -52, -56, 120, 82, 87, -64, -35, -120, -82, -112, 97, 25, -23, -52, 45, 105, 84, -64, 15, -41, -118, 51, -46, 103, 18, -4, 61, -108, 97, -92, 17, -114, -23, 66, -91, -64, -11, -17, 35, -91, 66, 38, -30, -17, -3, 126, 53, 114, 7, -100, -103, -41, -29, 99, -126, -125, 127, 2, -127, -127, 0, -7, 78, 15, 57, 91, -30, -120, 11, -59, 35, -88, -79, 101, 85, -21, -121, 28, -63, -93, -37, 82, -64, -90, -49, -39, -57, 117, 108, 0, 64, 50, 84, -73, -30, -15, 35, -85, 109, 1, 15, 34, -18, 114, -55, 26, -44, -30, -73, 41, 102, -102, -128, 33, -115, -46, -55, -63, 78, -37, 5, 127, -48, -11, 81, -71, -59, -79, 75, 24, -1, 52, -54, 77, 52, 73, -124, -124, 12, 53, -114, 3, -110, -33, -56, 12, -104, -98, -102, -82, 52, 88, -15, 112, -32, -109, -28, -3, 106, -90, -40, 126, 58, 47, 64, -8, -2, -95, -97, -119, -31, -53, 19, -97, 27, 18, -38, 73, 69, 33, 20, 116, 98, -9, -112, 9, 104, 114, 23, 2, -127, -127, 0, -59, -5, -68, 84, -11, -22, -10, 48, -110, 76, -94, 65, 90, -78, -113, 72, -66, 119, 80, -128, -60, 55, -88, 58, 103, -10, 62, -75, 64, -65, 86, -103, -106, -84, -104, 100, -45, -125, -100, 121, -78, -57, -88, -111, 102, 123, 12, 49, 53, -7, -9, 72, -96, 113, 35, -77, 32, 106, 102, -91, -49, 32, 28, 102, -99, -37, 37, 31, 124, -30, -99, -107, 81, 38, 90, -22, -15, 91, 37, -8, 55, 9, -16, 89, 97, -76, -32, 79, 6, 98, 95, 107, -107, -111, -3, -24, -17, -120, -110, -35, -117, -26, -2, 72, -125, -13, -128, -38, 96, -32, -27, 113, -87, 70, -101, 106, 55, 110, -59, 81, -44, -31, 114, -14, 39, -24, -29, 67, 2, -127, -127, 0, -127, 8, 101, -40, -54, 53, -11, 52, 34, 84, -46, 122, -2, 119, -7, -17, 116, 114, -60, -36, 63, 120, 118, -34, 29, 89, -98, -20, -57, 52, 114, -40, 102, 84, -113, 122, 102, -65, -124, 76, -47, 71, -103, 33, 125, 65, -78, 22, 26, -41, -128, 31, -47, 62, 22, 91, 86, 49, -6, 42, 94, 125, 72, 123, -124, 43, 78, 24, 16, 88, 6, 122, -82, 122, -31, -110, 52, -58, 28, -15, -29, -25, -96, -21, 105, -103, -108, 125, 122, -84, -99, 92, 89, -113, -30, -4, 34, 45, -111, 45, 124, 39, -95, 77, 127, -110, 75, 20, -57, -56, -107, -45, 18, 6, 113, 59, -119, -80, -67, -18, 88, 78, -32, -45, 44, 11, 99, 1, 2, -127, -128, 2, -107, -33, -27, -38, -38, -39, -123, -18, -75, 77, 19, -121, -103, -54, 39, -126, -36, -59, 112, 8, -123, 46, 18, -90, 9, 107, 26, 31, 78, -61, 15, -127, 9, 9, 110, 13, -119, 118, -102, 65, 59, 17, -38, 103, -78, -127, -121, 46, -39, -46, 71, -116, -107, -13, -15, 73, 43, -45, 85, -15, 52, -67, -58, -45, 68, 83, 108, 71, 30, -89, 14, -98, -19, 38, -67, 29, 76, 10, 93, -70, 29, 52, 20, 100, 113, -92, 35, 0, 45, -55, -48, 95, 123, -123, -55, -44, -105, 58, 102, -91, -71, 71, 100, 56, 105, -87, -86, -31, 39, -48, -15, -45, -117, -33, -16, 19, 16, 4, -10, -124, -39, 103, 90, -66, -27, 63, -22};
		byte[] encodedPublicKey = {48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -41, -26, 10, -62, -2, -97, 123, 113, -21, 88, -127, 93, 95, 96, 18, 44, 47, -97, -45, -125, 32, -85, -11, -123, 63, -70, -29, -95, 16, 21, 102, 60, 106, -105, -115, -90, 29, 6, 119, -54, -47, -70, 13, -94, -52, -86, 59, 61, 43, 1, 87, 69, -99, -30, -59, 102, -58, -97, 83, 22, -16, 84, 95, -114, -100, 19, 77, -77, -68, 39, 91, 95, -117, 44, 89, 105, 22, 107, -30, -77, 38, 108, 97, -34, 21, -79, 28, -12, 39, 12, 52, -101, 17, -36, -38, -60, -98, 17, 46, 79, 80, -53, -99, -123, 29, -79, -45, 119, 23, 14, -81, -35, -19, -107, 64, 89, 14, 102, 12, 113, 105, 45, 50, -100, 80, -33, -10, 93, -113, 22, 17, -75, -17, -63, 32, 36, 45, -55, 70, 33, 23, -61, 62, 49, -75, 45, 99, -83, 37, 41, -109, -32, -79, 48, 65, -76, -40, 62, -47, 25, 87, 55, -7, -37, -61, -18, -64, 120, 113, -44, 119, 75, 104, 40, -66, -93, -103, -1, -63, -3, 123, -72, 82, -15, 64, -109, 40, 64, -120, -46, 24, -116, 39, 33, 109, -56, -15, -79, -109, -67, -128, -16, 15, -24, 96, 98, -115, -93, 60, 7, -118, 76, -1, -21, 46, 37, 24, 62, -51, -9, 58, 82, -5, 83, -123, -19, 39, -84, -69, 67, 99, 69, -86, -92, 84, -59, -95, -101, 2, -81, 96, -19, -35, 53, 48, -121, 94, -27, 15, -67, 43, -46, -15, -32, 94, 105, 2, 3, 1, 0, 1};
		byte[] hardcodedServicePublicKey = {48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -97, 84, -15, -30, -56, 33, -24, -97, 49, -1, 104, -90, -79, -110, 26, 97, -27, -40, 73, 86, 46, 37, 108, 75, 108, 106, -37, -125, -67, 115, -102, -7, -80, 3, -3, -8, 51, -66, 106, -3, 95, 93, 124, 54, -113, 71, -44, 113, -25, -105, -45, 8, 114, 22, -21, 112, 118, -108, -96, -35, 71, -5, 24, -50, -78, -120, 69, 86, -57, -36, -21, -50, -64, 12, -58, 46, 50, -59, 29, 102, -23, -27, 81, 75, 2, -104, -125, 59, 103, 43, 97, -81, -94, 68, 72, -61, -119, 103, -127, 89, 28, 122, 70, 28, -89, 45, 92, 22, 66, 115, -18, 70, 41, -125, -89, -103, 18, -99, 26, 74, 46, 116, 44, 1, 90, 103, 7, -37, 52, 49, -52, -110, -47, 33, -125, 100, -100, 1, -95, 82, 65, -7, 53, 122, 10, -98, -79, -45, -75, -128, -33, 62, -46, 8, -89, 14, -48, -41, -13, 83, 34, 106, 47, -25, 10, -55, 77, 75, 110, -14, 64, -118, 29, -20, -96, -58, 77, 19, 36, 117, 53, -110, -53, -40, 13, -67, 102, 85, -126, -19, -119, -128, 81, -96, 8, 102, -36, 0, -105, -81, -19, -111, 47, -61, 33, -56, -86, -60, -43, 118, 21, -16, -110, -84, -8, 101, -32, 111, 106, 62, 32, 48, 110, 11, -99, 66, 81, 57, 5, -34, -123, 11, 39, 119, 103, -13, -49, -124, 50, -66, 13, -29, -114, -128, 38, -59, -87, 92, -120, -58, -30, -9, 126, 19, -12, 15, 2, 3, 1, 0, 1};
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey attestationServicePublicKey = keyFactory.generatePublic(publicKeySpec);
		EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(encodedPrivateKey);
		PrivateKey attestationServicePrivateKey = keyFactory.generatePrivate(privateKeySpec);


		ConfidentialServiceProxy serviceProxy = new ConfidentialServiceProxy(100);
		try {
			BigInteger publicSessionKeyPart = generator.modPow(privateSessionKeyPart, primeField);

			Message0 message0 = new Message0(attesterId, publicSessionKeyPart.toByteArray());
			byte[] serializedMessage0 = serializeMessage(MessageType.MESSAGE_0, message0);

			Response response = serviceProxy.invokeOrdered(serializedMessage0);

			Message1 message1 = (Message1) deserializeMessage(response.getPainData());
			if (message1 == null)
				System.exit(-1);
			EncodedKeySpec servicePublicKeySpec = new X509EncodedKeySpec(message1.getVerifierPublicKey());
			PublicKey servicePublicKey = keyFactory.generatePublic(servicePublicKeySpec);

			boolean isSignatureValid = verifySignature(servicePublicKey, message1.getSignatureOfSessionKeys(),
					message1.getVerifierPublicSessionKeyPart(), publicSessionKeyPart.toByteArray());
			if (isSignatureValid) {
				System.out.println("Signature is valid");
			} else {
				System.err.println("Signature is invalid. Exiting!");
				System.exit(-1);
			}

			BigInteger sharedSecretKeyNumber = new BigInteger(message1.getVerifierPublicSessionKeyPart())
					.modPow(privateSessionKeyPart, primeField);
			SecretKey sharedSecretKey = createSecretKey(sharedSecretKeyNumber.toString().toCharArray());

			boolean isMacValid = checkMac(sharedSecretKey, message1.getMac(),
					message1.getVerifierPublicSessionKeyPart(), message1.getVerifierPublicKey(),
					message1.getSignatureOfSessionKeys());
			if (isMacValid) {
				System.out.println("MAC is valid");
			} else {
				System.err.println("MAC is invalid. Exiting!");
				System.exit(-1);
			}

			if (Arrays.equals(servicePublicKey.getEncoded(), hardcodedServicePublicKey)) {
				System.out.println("Verifier public key is valid");
			} else {
				System.err.println("Verifier public key is invalid. Exiting!");
				System.exit(-1);
			}

			byte[] anchor = createHash(publicSessionKeyPart.toByteArray(),
					message1.getVerifierPublicSessionKeyPart());
			Evidence evidence = new Evidence(
					anchor,
					waTZVersion,
					claim,
					attestationServicePublicKey.getEncoded()
			);

			byte[] evidenceSignature = createSignature(attestationServicePrivateKey, anchor,
					waTZVersion.getBytes(), claim, attestationServicePublicKey.getEncoded());
			byte[] mac = createMac(sharedSecretKey, publicSessionKeyPart.toByteArray(), anchor,
					waTZVersion.getBytes(), claim, attestationServicePublicKey.getEncoded(),
					evidenceSignature);
			Message2 message2 = new Message2(publicSessionKeyPart.toByteArray(),
					evidence, evidenceSignature, mac);
			byte[] serializedMessage2 = serializeMessage(MessageType.MESSAGE_2, message2);
			response = serviceProxy.invokeOrdered(serializedMessage0);


		} finally {
			serviceProxy.close();
		}
	}

	private static byte[] createSignature(PrivateKey signingKey, byte[]... contents) throws InvalidKeyException, SignatureException {
		signingEngine.initSign(signingKey);
		for (byte[] content : contents) {
			signingEngine.update(content);
		}
		return signingEngine.sign();
	}

	private static byte[] createHash(byte[]... contents) {
		for (byte[] content : contents) {
			messageDigest.update(content);
		}
		return messageDigest.digest();
	}

	private static SecretKey createSecretKey(char[] password) throws InvalidKeySpecException {
		KeySpec spec = new PBEKeySpec(password);
		return new SecretKeySpec(secretKeyFactory.generateSecret(spec).getEncoded(), "AES");
	}

	private static boolean checkMac(SecretKey secretKey, byte[] mac, byte[]... contents) throws InvalidKeyException {
		return Arrays.equals(createMac(secretKey, contents), mac);
	}

	private static byte[] createMac(SecretKey secretKey, byte[]... contents) throws InvalidKeyException {
		macEngine.init(secretKey);
		for (byte[] content : contents) {
			macEngine.update(content);
		}
		return macEngine.doFinal();
	}

	private static boolean verifySignature(PublicKey publicKey, byte[] signature, byte[]... contents) throws InvalidKeyException, SignatureException {
		signingEngine.initVerify(publicKey);
		for (byte[] content : contents) {
			signingEngine.update(content);
		}
		return signingEngine.verify(signature);
	}

	private static SireMessage deserializeMessage(byte[] serializedMessage) {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedMessage);
			 ObjectInputStream in = new ObjectInputStream(bis)) {
			MessageType messageType = MessageType.getMessageType(in.read());
			SireMessage result = null;
			switch (messageType) {
				case MESSAGE_0 -> result = new Message0();
				case MESSAGE_1 -> result = new Message1();
			}
			if (result != null)
				result.readExternal(in);
			return result;
		} catch (IOException | ClassNotFoundException e) {
			System.err.println("Failed to deserialized a message");
			e.printStackTrace();
		}
		return null;
	}

	private static byte[] serializeMessage(MessageType type, SireMessage message) {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutputStream out = new ObjectOutputStream(bos)) {
			out.write(type.ordinal());
			message.writeExternal(out);
			out.flush();
			bos.flush();
			return bos.toByteArray();
		} catch (IOException e) {
			System.err.println("Failed to serialize a message");
			e.printStackTrace();
		}
		return null;
	}

	private static BigInteger getRandomNumber() {
		BigInteger rndBig = new BigInteger(subField.bitLength() - 1, rndGenerator);
		if (rndBig.compareTo(BigInteger.ZERO) == 0) {
			rndBig = rndBig.add(BigInteger.ONE);
		}

		return rndBig;
	}
}
