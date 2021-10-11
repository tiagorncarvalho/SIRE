package sire.playground;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author robin
 */
public class SchnorrSignature {
	private static BigInteger order;
	private static ECPoint generator;
	private static final SecureRandom rndGenerator = new SecureRandom("sire".getBytes());
	private static MessageDigest messageDigest;

	public static void main(String[] args) throws NoSuchAlgorithmException, SecretSharingException {
		messageDigest = MessageDigest.getInstance("SHA256");
		BigInteger prime = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
		order = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16);
		BigInteger a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16);
		BigInteger b = new BigInteger("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16);
		BigInteger generatorX = new BigInteger("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16);
		BigInteger generatorY = new BigInteger("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", 16);
		BigInteger cofactor = prime.divide(order);
		ECCurve curve = new ECCurve.Fp(prime, a, b, order, cofactor);
		generator = curve.createPoint(generatorX, generatorY);
		System.out.println("Cofactor: " + cofactor);

		byte[] message = "Schnorr".getBytes();

		System.out.println("\n\n========= Traditional Schnorr Signature =========");
		signatureUsingBouncyCastle(message);
		System.out.println("\n\n========= Threshold Schnorr Signature =========");
		thresholdSignature(message,1, 4);
	}

	private static void thresholdSignature(byte[] message, int t, int n) throws SecretSharingException {
		BigInteger[] shareholders = new BigInteger[n];
		for (int i = 0; i < n; i++) {
			shareholders[i] = BigInteger.valueOf(i + 1);
		}

		//Generating keys
		System.out.println("Generating a key pair...");
		BigInteger secretKey = getRandomNumber(order);//must be generated collaboratively
		ECPoint Y = generator.multiply(secretKey);
		Polynomial secretKeyPolynomial = new Polynomial(order, t, secretKey, rndGenerator);
		ECPoint[] secretKeyCommitment = computeCommitment(secretKeyPolynomial);
		Share[] secretKeyShares = new Share[n];

		for (int i = 0; i < shareholders.length; i++) {
			BigInteger shareholder = shareholders[i];
			secretKeyShares[i] = new Share(shareholder, secretKeyPolynomial.evaluateAt(shareholder));
		}

		//Generating the signature
		System.out.println("Generating a signature...");
		BigInteger randomSecret = getRandomNumber(order);//must be generated collaboratively
		ECPoint V = generator.multiply(randomSecret);
		Polynomial randomSecretPolynomial = new Polynomial(order, t, randomSecret, rndGenerator);
		ECPoint[] randomSecretCommitment = computeCommitment(randomSecretPolynomial);
		Share[] randomSecretShares = new Share[n];
		for (int i = 0; i < shareholders.length; i++) {
			BigInteger shareholder = shareholders[i];
			randomSecretShares[i] = new Share(shareholder, randomSecretPolynomial.evaluateAt(shareholder));
		}

		BigInteger hash = new BigInteger(computeHash(message, V.getEncoded(true)));

		Share[] partialSignatures = new Share[n];
		for (int i = 0; i < partialSignatures.length; i++) {
			BigInteger partialSignature = randomSecretShares[i].getShare().add(hash.multiply(secretKeyShares[i].getShare()));
			partialSignatures[i] = new Share(shareholders[i], partialSignature);
		}

		//Verifying the partial signatures
		System.out.println("Verifying the partial signatures...");
		for (Share partialSignature : partialSignatures) {
			boolean isPartialSignatureValid = verifyPartialSignature(hash, V, Y, partialSignature,
					secretKeyCommitment, randomSecretCommitment);
			if (!isPartialSignatureValid) {
				throw new IllegalStateException("Partial signature from "
						+ partialSignature.getShareholder() + " is invalid");
			}
		}
		System.out.println("Partial signatures are valid");

		//Combining the partial signatures
		System.out.println("Combining the partial signatures...");
		Polynomial sigmaPolynomial = new Polynomial(order, partialSignatures);
		BigInteger sigma = sigmaPolynomial.evaluateAt(BigInteger.ZERO);

		//Verifying the signature
		boolean isValid = verifySignature(message, Y, V, sigma);

		if (isValid) {
			System.out.println("Signature is valid");
		} else {
			System.out.println("Signature is invalid");
		}
	}

	private static boolean verifyPartialSignature(BigInteger hash, ECPoint V, ECPoint Y, Share partialSignature,
												  ECPoint[] secretKeyCommitment, ECPoint[] randomSecretCommitment) {
		ECPoint leftSide = generator.multiply(partialSignature.getShare());
		ECPoint combinedSecretKeyCommitment = secretKeyCommitment[secretKeyCommitment.length - 1];
		ECPoint combinedRandomSecretCommitment = randomSecretCommitment[randomSecretCommitment.length - 1];
		BigInteger shareholder = partialSignature.getShareholder();
		for (int i = 0; i < secretKeyCommitment.length - 1; i++) {
			int k = secretKeyCommitment.length - 1 - i;
			combinedSecretKeyCommitment = combinedSecretKeyCommitment.add(secretKeyCommitment[i]
					.multiply(shareholder.pow(k)));
			combinedRandomSecretCommitment = combinedRandomSecretCommitment.add(randomSecretCommitment[i]
					.multiply(shareholder.pow(k)));
		}
		ECPoint rightSide = combinedRandomSecretCommitment
				.add(combinedSecretKeyCommitment.multiply(hash));
		return leftSide.equals(rightSide);
	}

	private static void signatureUsingBouncyCastle(byte[] message) {
		//Generating keys
		System.out.println("Generating a key pair...");
		BigInteger x = getRandomNumber(order);
		ECPoint Y = generator.multiply(x);

		//Generating the signature
		System.out.println("Generating a signature...");
		BigInteger e = getRandomNumber(order);
		ECPoint V = generator.multiply(e);
		BigInteger hash = new BigInteger(computeHash(message, V.getEncoded(true)));
		BigInteger sigma = e.add(hash.multiply(x)).mod(order);

		//Verifying the signature
		boolean isValid = verifySignature(message, Y, V, sigma);

		if (isValid) {
			System.out.println("Signature is valid");
		} else {
			System.out.println("Signature is invalid");
		}
	}

	private static boolean verifySignature(byte[] message, ECPoint Y, ECPoint V, BigInteger sigma) {
		System.out.println("Verifying the signature...");
		if (sigma.compareTo(order) >= 0) {
			System.out.println("Signature is invalid. Sigma is not in Z_q");
			System.exit(-1);
		}
		BigInteger hash = new BigInteger(computeHash(message, V.getEncoded(true)));

		ECPoint leftSide = generator.multiply(sigma);
		ECPoint rightSide = V.add(Y.multiply(hash));
		return leftSide.equals(rightSide);
	}

	private static byte[] computeHash(byte[]... contents) {
		for (byte[] content : contents) {
			messageDigest.update(content);
		}
		return messageDigest.digest();
	}

	private static BigInteger getRandomNumber(BigInteger field) {
		BigInteger rndBig = new BigInteger(field.bitLength() - 1, rndGenerator);
		if (rndBig.compareTo(BigInteger.ZERO) == 0) {
			rndBig = rndBig.add(BigInteger.ONE);
		}

		return rndBig;
	}

	private static ECPoint[] computeCommitment(Polynomial polynomial) {
		BigInteger[] coefficients = polynomial.getCoefficients();
		ECPoint[] commitment = new ECPoint[coefficients.length];
		for (int i = 0; i < commitment.length; i++) {
			commitment[i] = generator.multiply(coefficients[i]);
		}
		return commitment;
	}
}
