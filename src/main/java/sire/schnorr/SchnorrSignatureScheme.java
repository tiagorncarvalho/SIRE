package sire.schnorr;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.interpolation.LagrangeInterpolation;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

/**
 * @author robin
 */
public class SchnorrSignatureScheme {
	private final MessageDigest messageDigest;
	private final ECPoint generator;
	private final BigInteger order;
	private final Set<BigInteger> corruptedShareholders;
	private final InterpolationStrategy interpolationStrategy;
	private final ECCurve curve;

	public SchnorrSignatureScheme() throws NoSuchAlgorithmException {
		messageDigest = MessageDigest.getInstance("SHA256");

		//secp256r1 curve domain parameters
		BigInteger prime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
		order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
		BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
		BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
		byte[] compressedGenerator = new BigInteger("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).toByteArray();

		BigInteger cofactor = prime.divide(order);
		curve = new ECCurve.Fp(prime, a, b, order, cofactor);
		generator = curve.decodePoint(compressedGenerator);
		corruptedShareholders = new HashSet<>();
		this.interpolationStrategy = new LagrangeInterpolation(order);
	}

	public void clearCorruptedShareholderList() {
		corruptedShareholders.clear();
	}

	public SchnorrSignature computeSignature(byte[] data, BigInteger signingPrivateKey, ECPoint signingPublicKey,
											 BigInteger randomPrivateKey, ECPoint randomPublicKey) {
		BigInteger hash = new BigInteger(computeHash(data, randomPublicKey.getEncoded(true)));
		BigInteger sigma = randomPrivateKey.add(hash.multiply(signingPrivateKey)).mod(order);
		return new SchnorrSignature(sigma.toByteArray(), signingPublicKey.getEncoded(true),
				randomPublicKey.getEncoded(true));
	}

	public BigInteger computePartialSignature(byte[] data, BigInteger signingKeyShare,
											  BigInteger randomKeyShare, ECPoint randomPublicKey) {
		BigInteger hash = new BigInteger(computeHash(data, randomPublicKey.getEncoded(true)));
		return randomKeyShare.add(hash.multiply(signingKeyShare));
	}

	public BigInteger combinePartialSignatures(int f, byte[] data, EllipticCurveCommitment signingKeyCommitment,
											   EllipticCurveCommitment randomKeyCommitment,
											   ECPoint randomPublicKey,
											   Share... partialSignatures) throws SecretSharingException {
		Share[] minimumShares = new Share[corruptedShareholders.size() < f ? f + 2 : f + 1];
		for (int i = 0, j = 0; i < partialSignatures.length && j < minimumShares.length; i++) {
			Share share = partialSignatures[i];
			if (!corruptedShareholders.contains(share.getShareholder()))
				minimumShares[j++] = share;
		}
		BigInteger sigma;
		Polynomial sigmaPolynomial = new Polynomial(order, minimumShares);
		if (sigmaPolynomial.getDegree() != f) {
			BigInteger hash = new BigInteger(computeHash(data, randomPublicKey.getEncoded(true)));
			minimumShares = new Share[f + 1];
			int counter = 0;
			for (Share partialSignature : partialSignatures) {
				if (corruptedShareholders.contains(partialSignature.getShareholder())) {
					continue;
				}
				boolean isValid = verifyPartialSignature(hash, partialSignature, signingKeyCommitment.getCommitment(),
						randomKeyCommitment.getCommitment());
				if (counter <= f && isValid) {
					minimumShares[counter++] = partialSignature;
				}
				if (!isValid) {
					corruptedShareholders.add(partialSignature.getShareholder());
				}
			}

			if (counter <= f) {
				throw new SecretSharingException("Not enough valid shares!");
			}
			sigma = interpolationStrategy.interpolateAt(BigInteger.ZERO, minimumShares);
		} else {
			sigma = sigmaPolynomial.getConstant();
		}
		return sigma;
	}

	public boolean verifySignature(byte[] data, ECPoint signingPublicKey, ECPoint randomPublicKey,
									BigInteger sigma) {
		if (sigma.compareTo(order) >= 0) {
			return false;
		}
		BigInteger hash = new BigInteger(computeHash(data, randomPublicKey.getEncoded(true)));

		ECPoint leftSide = generator.multiply(sigma);
		ECPoint rightSide = randomPublicKey.add(signingPublicKey.multiply(hash));

		return leftSide.equals(rightSide);
	}

	private boolean verifyPartialSignature(BigInteger hash, Share partialSignature,
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

	public ECPoint getGenerator() {
		return generator;
	}

	public ECCurve getCurve() {
		return curve;
	}

	private byte[] computeHash(byte[]... contents) {
		for (byte[] content : contents) {
			messageDigest.update(content);
		}
		return messageDigest.digest();
	}

	public ECPoint decodePublicKey(byte[] encodedKey) {
		return curve.decodePoint(encodedKey);
	}

	public static byte[] encodePublicKey(ECPoint publicKey) {
		return publicKey.getEncoded(true);
	}
}
