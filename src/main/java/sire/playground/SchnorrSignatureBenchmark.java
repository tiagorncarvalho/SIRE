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
import java.util.ArrayList;
import java.util.Arrays;

/**
 * @author robin
 */
public class SchnorrSignatureBenchmark {
	private static BigInteger order;
	private static ECPoint generator;
	private static final SecureRandom rndGenerator = new SecureRandom("sire".getBytes());
	private static MessageDigest messageDigest;

	public static void main(String[] args) throws NoSuchAlgorithmException, SecretSharingException {
		if (args.length != 3) {
			System.out.println("USAGE: ... sire.playground.SchnorrSignatureBenchmark <threshold> <warm up iterations> <test iterations>");
			System.exit(-1);
		}


		messageDigest = MessageDigest.getInstance("SHA256");
		BigInteger prime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
		order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
		BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
		BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
		byte[] compressedGenerator = new BigInteger("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).toByteArray();

		BigInteger cofactor = prime.divide(order);
		ECCurve curve = new ECCurve.Fp(prime, a, b, order, cofactor);
		generator = curve.decodePoint(compressedGenerator);
		System.out.println("Cofactor: " + cofactor);

		int threshold = Integer.parseInt(args[0]);
		int n = 3 * threshold + 1;
		int warmUpIterations = Integer.parseInt(args[1]);
		int testIterations = Integer.parseInt(args[2]);

		System.out.println("t = " + threshold);
		System.out.println("n = " + n);

		byte[] message = new byte[1024];
		rndGenerator.nextBytes(message);

		System.out.println("Warming up (" + warmUpIterations + " iterations)");
		if (warmUpIterations > 0) {
			runTests(false, warmUpIterations, message, threshold, n);
		}

		System.out.println("Running test (" + testIterations + " iterations)");
		if (testIterations > 0) {
			runTests(true, testIterations, message, threshold, n);
		}
	}

	private static void runTests(boolean printResults, int nTests, byte[] message, int t, int n) throws SecretSharingException {
		BigInteger[] shareholders = new BigInteger[n];
		for (int i = 0; i < n; i++) {
			shareholders[i] = BigInteger.valueOf(i + 1);
		}

		long[] secretKeyGenerationTimes = new long[nTests];
		long[] publicKeyComputationTimes = new long[nTests];
		long[] secretKeySharesComputationTimes = new long[nTests];
		long[] secretKeyCommitmentComputationTimes = new long[nTests];

		long[] randomSecretGenerationTimes = new long[nTests];
		long[] randomPublicComputationTimes = new long[nTests];
		long[] randomSecretSharesComputationTimes = new long[nTests];
		long[] randomSecretCommitmentComputationTimes = new long[nTests];

		long[] partialSignatureComputationTimes = new long[nTests];
		long[] partialSignaturesVerificationTimes = new long[nTests];

		long[] partialSignatureCombinationTimes = new long[nTests];

		long[] signatureVerificationTimes = new long[nTests];

		long start, end;
		for (int nT = 0; nT < nTests; nT++) {
			long secretKeyGenerationTime;
			long publicKeyComputationTime;
			long secretKeySharesComputationTime;
			long secretKeyCommitmentComputationTime;

			long randomSecretGenerationTime;
			long randomPublicComputationTime;
			long randomSecretSharesComputationTime;
			long randomSecretCommitmentComputationTime;

			long partialSignatureComputationTime;
			long partialSignaturesVerificationTime;

			long partialSignatureCombinationTime;

			long signatureVerificationTime;

			//Generating keys
			start = System.nanoTime();
			BigInteger secretKey = getRandomNumber(order);
			end = System.nanoTime();
			secretKeyGenerationTime = end - start;

			start = System.nanoTime();
			ECPoint publicKey = generator.multiply(secretKey);
			end = System.nanoTime();
			publicKeyComputationTime = end - start;

			start = System.nanoTime();
			Polynomial secretKeyPolynomial = new Polynomial(order, t, secretKey, rndGenerator);
			Share[] secretKeyShares = new Share[n];
			for (int i = 0; i < shareholders.length; i++) {
				BigInteger shareholder = shareholders[i];
				secretKeyShares[i] = new Share(shareholder, secretKeyPolynomial.evaluateAt(shareholder));
			}
			end = System.nanoTime();
			secretKeySharesComputationTime = end - start;

			start = System.nanoTime();
			BigInteger[] coefficients = secretKeyPolynomial.getCoefficients();
			ECPoint[] secretKeyCommitment = new ECPoint[coefficients.length];
			for (int i = 0; i < secretKeyCommitment.length; i++) {
				secretKeyCommitment[i] = generator.multiply(coefficients[i]);
			}
			end = System.nanoTime();
			secretKeyCommitmentComputationTime = end - start;

			//Generating a signature
			start = System.nanoTime();
			BigInteger randomSecret = getRandomNumber(order);
			end = System.nanoTime();
			randomSecretGenerationTime = end - start;

			start = System.nanoTime();
			ECPoint randomPublic = generator.multiply(randomSecret);
			end = System.nanoTime();
			randomPublicComputationTime = end - start;

			start = System.nanoTime();
			Polynomial randomSecretPolynomial = new Polynomial(order, t, randomSecret, rndGenerator);
			Share[] randomSecretShares = new Share[n];
			for (int i = 0; i < shareholders.length; i++) {
				BigInteger shareholder = shareholders[i];
				randomSecretShares[i] = new Share(shareholder, randomSecretPolynomial.evaluateAt(shareholder));
			}
			end = System.nanoTime();
			randomSecretSharesComputationTime = end - start;

			start = System.nanoTime();
			coefficients = randomSecretPolynomial.getCoefficients();
			ECPoint[] randomSecretCommitment = new ECPoint[coefficients.length];
			for (int i = 0; i < randomSecretCommitment.length; i++) {
				randomSecretCommitment[i] = generator.multiply(coefficients[i]);
			}
			end = System.nanoTime();
			randomSecretCommitmentComputationTime = end - start;

			int[] selectedShareholdersIndex = selectShareholders(t + 1, shareholders);

			Share[] partialSignatures = new Share[selectedShareholdersIndex.length];
			int measurementShareholderIndex = selectedShareholdersIndex[0];
			start = System.nanoTime();
			BigInteger hash = new BigInteger(computeHash(message, randomPublic.getEncoded(true)));
			BigInteger partialSignature = randomSecretShares[measurementShareholderIndex].getShare()
					.add(hash.multiply(secretKeyShares[measurementShareholderIndex].getShare()));
			partialSignatures[0] = new Share(shareholders[measurementShareholderIndex], partialSignature);
			end = System.nanoTime();
			partialSignatureComputationTime = end - start;
			for (int i = 1; i < selectedShareholdersIndex.length; i++) {
				int shareholderIndex = selectedShareholdersIndex[i];
				partialSignature = randomSecretShares[shareholderIndex].getShare()
						.add(hash.multiply(secretKeyShares[shareholderIndex].getShare()));
				partialSignatures[i] = new Share(shareholders[shareholderIndex], partialSignature);
			}

			//Verifying the partial signatures
			start = System.nanoTime();
			hash = new BigInteger(computeHash(message, randomPublic.getEncoded(true)));
			for (Share partialSignatureShare : partialSignatures) {
				boolean isPartialSignatureValid = verifyPartialSignature(hash,
						partialSignatureShare, secretKeyCommitment, randomSecretCommitment);
				if (!isPartialSignatureValid) {
					throw new IllegalStateException("Partial signature from "
							+ partialSignatureShare.getShareholder() + " is invalid");
				}
			}
			end = System.nanoTime();
			partialSignaturesVerificationTime = end - start;

			//Combining the partial signatures
			start = System.nanoTime();
			Polynomial sigmaPolynomial = new Polynomial(order, partialSignatures);
			BigInteger sigma = sigmaPolynomial.evaluateAt(BigInteger.ZERO);
			end = System.nanoTime();
			partialSignatureCombinationTime = end - start;

			//Verifying the signature
			start = System.nanoTime();
			boolean isValid = verifySignature(message, publicKey, randomPublic, sigma);
			end = System.nanoTime();
			signatureVerificationTime = end - start;

			if (!isValid) {
				throw new IllegalStateException("Signature is invalid");
			}
			secretKeyGenerationTimes[nT] = secretKeyGenerationTime;
			publicKeyComputationTimes[nT] = publicKeyComputationTime;
			secretKeySharesComputationTimes[nT] = secretKeySharesComputationTime;
			secretKeyCommitmentComputationTimes[nT] = secretKeyCommitmentComputationTime;
			randomSecretGenerationTimes[nT] = randomSecretGenerationTime;
			randomPublicComputationTimes[nT] = randomPublicComputationTime;
			randomSecretSharesComputationTimes[nT] = randomSecretSharesComputationTime;
			randomSecretCommitmentComputationTimes[nT] = randomSecretCommitmentComputationTime;
			partialSignatureComputationTimes[nT] = partialSignatureComputationTime;
			partialSignaturesVerificationTimes[nT] = partialSignaturesVerificationTime;
			partialSignatureCombinationTimes[nT] = partialSignatureCombinationTime;
			signatureVerificationTimes[nT] = signatureVerificationTime;
		}

		if (printResults) {
			double secretKeyGenerationTime = computeAverage(secretKeyGenerationTimes);
			double publicKeyComputationTime = computeAverage(publicKeyComputationTimes);
			double secretKeySharesComputationTime = computeAverage(secretKeySharesComputationTimes);
			double secretKeyCommitmentComputationTime = computeAverage(secretKeyCommitmentComputationTimes);
			double randomSecretGenerationTime = computeAverage(randomSecretGenerationTimes);
			double randomPublicComputationTime = computeAverage(randomPublicComputationTimes);
			double randomSecretSharesComputationTime = computeAverage(randomSecretSharesComputationTimes);
			double randomSecretCommitmentComputationTime = computeAverage(randomSecretCommitmentComputationTimes);
			double partialSignatureComputationTime = computeAverage(partialSignatureComputationTimes);
			double partialSignaturesVerificationTime = computeAverage(partialSignaturesVerificationTimes);
			double partialSignatureCombinationTime = computeAverage(partialSignatureCombinationTimes);
			double signatureVerificationTime = computeAverage(signatureVerificationTimes);

			System.out.printf("Secret key generation (at 1 shareholder): %.6f ms\n", secretKeyGenerationTime);
			System.out.printf("Public key computation (at 1 shareholder): %.6f ms\n", publicKeyComputationTime);
			System.out.printf("Secret key shares computation (at 1 shareholder): %.6f ms\n", secretKeySharesComputationTime);
			System.out.printf("Secret key commitment computation (at 1 shareholder): %.6f ms\n", secretKeyCommitmentComputationTime);
			System.out.printf("Random secret generation (at 1 shareholder): %.6f ms\n", randomSecretGenerationTime);
			System.out.printf("Random public computation (at 1 shareholder): %.6f ms\n", randomPublicComputationTime);
			System.out.printf("Random secret shares (at 1 shareholder): %.6f ms\n", randomSecretSharesComputationTime);
			System.out.printf("Random secret commitment (at 1 shareholder): %.6f ms\n", randomSecretCommitmentComputationTime);
			System.out.printf("Partial signature computation (1 share): %.6f ms\n", partialSignatureComputationTime);
			System.out.printf("Partial signatures verification (t+1 shares): %.6f ms\n", partialSignaturesVerificationTime);
			System.out.printf("Partial signature combination (using t+1 shares): %.6f ms\n", partialSignatureCombinationTime);
			System.out.printf("Signature verification: %.6f ms", signatureVerificationTime);
			System.out.printf("\nTotal signing + verification (with partial verifications): %.6f ms\n",
					randomSecretGenerationTime + randomPublicComputationTime + randomSecretSharesComputationTime
							+ randomSecretCommitmentComputationTime + partialSignatureComputationTime
							+ partialSignaturesVerificationTime + partialSignatureCombinationTime
							+ signatureVerificationTime);
			System.out.printf("Total signing + verification (without partial verification): %.6f ms\n",
					randomSecretGenerationTime + randomPublicComputationTime + randomSecretSharesComputationTime
							+ randomSecretCommitmentComputationTime + partialSignatureComputationTime
							+ partialSignatureCombinationTime + signatureVerificationTime);
		}
	}

	private static int[] selectShareholders(int n, BigInteger[] shareholders) {
		int[] indexes = new int[n];
		ArrayList<Integer> collector = new ArrayList<>(shareholders.length);
		for (int i = 0; i < shareholders.length; i++) {
			collector.add(i);
		}

		for (int i = 0; i < indexes.length; i++) {
			int rndNumber = rndGenerator.nextInt(collector.size());
			indexes[i] = collector.get(rndNumber);
			collector.remove(rndNumber);
		}
		return indexes;
	}

	private static double computeAverage(long[] values) {
		return (double) Arrays.stream(values).sum() / (double)values.length / 1000000.0D;
	}

	private static boolean verifyPartialSignature(BigInteger hash, Share partialSignature,
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

	private static boolean verifySignature(byte[] message, ECPoint Y, ECPoint V, BigInteger sigma) {
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
}
