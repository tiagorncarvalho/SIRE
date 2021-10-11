package sire.schnorr;

import org.bouncycastle.math.ec.ECPoint;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class PublicPartialSignature {
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
		signingKeyCommitment.writeExternal(out);
		randomKeyCommitment.writeExternal(out);
		byte[] encoded = randomPublicKey.getEncoded(true);
		out.writeInt(encoded.length);
		out.write(encoded);
	}

	public static PublicPartialSignature deserialize(SchnorrSignatureScheme schnorrSignatureScheme, ObjectInput in) throws IOException, ClassNotFoundException {
		EllipticCurveCommitment signingKeyCommitment = new EllipticCurveCommitment(schnorrSignatureScheme.getCurve());
		signingKeyCommitment.readExternal(in);
		EllipticCurveCommitment randomKeyCommitment = new EllipticCurveCommitment(schnorrSignatureScheme.getCurve());
		randomKeyCommitment.readExternal(in);

		byte[] encoded = new byte[in.readInt()];
		in.readFully(encoded);
		ECPoint randomPublicKey = schnorrSignatureScheme.decodePublicKey(encoded);
		return new PublicPartialSignature(signingKeyCommitment, randomKeyCommitment , randomPublicKey);
	}
}
