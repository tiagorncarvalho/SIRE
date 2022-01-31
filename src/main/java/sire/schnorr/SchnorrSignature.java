package sire.schnorr;

import sire.utils.ProtoUtils;

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
		ProtoUtils.writeByteArray(out, sigma);
		ProtoUtils.writeByteArray(out, signingPublicKey);
		ProtoUtils.writeByteArray(out, randomPublicKey);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		sigma = ProtoUtils.readByteArray(in);
		signingPublicKey = ProtoUtils.readByteArray(in);
		randomPublicKey = ProtoUtils.readByteArray(in);
	}
}
