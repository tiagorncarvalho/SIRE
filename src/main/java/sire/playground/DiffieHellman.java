package sire.playground;

import org.bouncycastle.math.ec.ECPoint;
import sire.schnorr.SchnorrSignatureScheme;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

/**
 * @author robin
 */
public class DiffieHellman {
	public static void main(String[] args) throws NoSuchAlgorithmException {
		BigInteger privateKeyA = new BigInteger("34619214790742785527999706365024251903079091354721409475031021805278641187712");
		BigInteger privateKeyB = new BigInteger("17392669121939651647478634347602696394386899183641862312389911669748253672486");

		SchnorrSignatureScheme signatureScheme = new SchnorrSignatureScheme();
		ECPoint generator = signatureScheme.getGenerator();

		ECPoint publicKeyA = generator.multiply(privateKeyA);
		ECPoint publicKeyB = generator.multiply(privateKeyB);

		ECPoint sharedSecretPointA = publicKeyB.multiply(privateKeyA);
		ECPoint sharedSecretPointB = publicKeyA.multiply(privateKeyB);

		if (!sharedSecretPointA.equals(sharedSecretPointB))
			throw new IllegalStateException("Shared secret are different");

		BigInteger sharedSecretA = sharedSecretPointA.normalize().getXCoord().toBigInteger();
		BigInteger sharedSecretB = sharedSecretPointB.normalize().getXCoord().toBigInteger();

		System.out.println(sharedSecretA.toString(16));
		System.out.println(sharedSecretB.toString(16));
	}
}
