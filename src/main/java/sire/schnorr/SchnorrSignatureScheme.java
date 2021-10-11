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
		BigInteger prime = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
		order = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16);
		BigInteger a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16);
		BigInteger b = new BigInteger("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16);
		BigInteger generatorX = new BigInteger("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16);
		BigInteger generatorY = new BigInteger("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", 16);
		BigInteger cofactor = prime.divide(order);
		curve = new ECCurve.Fp(prime, a, b, order, cofactor);
		generator = curve.createPoint(generatorX, generatorY);
		corruptedShareholders = new HashSet<>();
		this.interpolationStrategy = new LagrangeInterpolation(order);
	}

	public void clearCorruptedShareholderList() {
		corruptedShareholders.clear();
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
}
