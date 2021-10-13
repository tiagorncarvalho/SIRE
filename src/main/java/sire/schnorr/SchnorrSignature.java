package sire.schnorr;

import sire.Utils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class SchnorrSignature implements Externalizable {
	private byte[] sigma;
	private byte[] signingPublicKey;
	private byte[] randomPublicKey;

	public SchnorrSignature() {
	}

	public SchnorrSignature(byte[] sigma, byte[] signingPublicKey, byte[] randomPublicKey) {
		this.sigma = sigma;
		this.signingPublicKey = signingPublicKey;
		this.randomPublicKey = randomPublicKey;
	}

	public byte[] getSigma() {
		return sigma;
	}

	public byte[] getSigningPublicKey() {
		return signingPublicKey;
	}

	public byte[] getRandomPublicKey() {
		return randomPublicKey;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		Utils.writeByteArray(out, sigma);
		Utils.writeByteArray(out, signingPublicKey);
		Utils.writeByteArray(out, randomPublicKey);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		sigma = Utils.readByteArray(in);
		signingPublicKey = Utils.readByteArray(in);
		randomPublicKey = Utils.readByteArray(in);
	}
}
