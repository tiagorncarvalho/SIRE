package sire.schnorr;

import org.bouncycastle.math.ec.ECPoint;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.util.Arrays;

/**
 * @author robin
 */
public class PublicPartialSignature implements Serializable {
	private final EllipticCurveCommitment signingKeyCommitment;
	private final EllipticCurveCommitment randomKeyCommitment;
	private final ECPoint randomPublicKey;

	public PublicPartialSignature(EllipticCurveCommitment signingKeyCommitment,
								  EllipticCurveCommitment randomKeyCommitment,
								  ECPoint randomPublicKey) {

		this.signingKeyCommitment = signingKeyCommitment;
		this.randomKeyCommitment = randomKeyCommitment;
		this.randomPublicKey = randomPublicKey;
	}

	public EllipticCurveCommitment getSigningKeyCommitment() {
		return signingKeyCommitment;
	}

	public EllipticCurveCommitment getRandomKeyCommitment() {
		return randomKeyCommitment;
	}

	public ECPoint getRandomPublicKey() {
		return randomPublicKey;
	}

	public void serialize(ObjectOutput out) throws IOException {
		System.out.println("Signing key comm " + signingKeyCommitment.toString());
		signingKeyCommitment.writeExternal(out);
		System.out.println("Random key comm " + randomKeyCommitment.toString());
		randomKeyCommitment.writeExternal(out);
		byte[] encoded = randomPublicKey.getEncoded(true);
		System.out.println("Encoded " + Arrays.toString(encoded));
		out.writeInt(encoded.length);
		out.write(encoded);
	}

	public static PublicPartialSignature deserialize(SchnorrSignatureScheme schnorrSignatureScheme, ObjectInput in) throws IOException, ClassNotFoundException {
		EllipticCurveCommitment signingKeyCommitment = new EllipticCurveCommitment(schnorrSignatureScheme.getCurve());
		signingKeyCommitment.readExternal(in);
		System.out.println("Signing key comm " + signingKeyCommitment.toString());
		EllipticCurveCommitment randomKeyCommitment = new EllipticCurveCommitment(schnorrSignatureScheme.getCurve());
		randomKeyCommitment.readExternal(in);
		System.out.println("Random key comm " + randomKeyCommitment.toString());

		byte[] encoded = new byte[in.readInt()];
		in.readFully(encoded);
		ECPoint randomPublicKey = schnorrSignatureScheme.decodePublicKey(encoded);
		System.out.println("Encoded " + Arrays.toString(encoded));
		return new PublicPartialSignature(signingKeyCommitment, randomKeyCommitment , randomPublicKey);
	}

}
