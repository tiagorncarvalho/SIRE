package sire.messages;

import sire.Utils;
import sire.proxy.Evidence;
import sire.schnorr.SchnorrSignature;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Message2 extends SireMessage {
	private byte[] encodedAttesterSessionPublicKey;
	private Evidence evidence;
	private SchnorrSignature evidenceSignature;
	private byte[] mac;

	public Message2() {}

	public Message2(byte[] encodedAttesterSessionPublicKey, Evidence evidence,
					SchnorrSignature evidenceSignature, byte[] mac) {
		this.encodedAttesterSessionPublicKey = encodedAttesterSessionPublicKey;
		this.evidence = evidence;
		this.evidenceSignature = evidenceSignature;
		this.mac = mac;
	}

	public byte[] getEncodedAttesterSessionPublicKey() {
		return encodedAttesterSessionPublicKey;
	}

	public Evidence getEvidence() {
		return evidence;
	}

	public SchnorrSignature getEvidenceSignature() {
		return evidenceSignature;
	}

	public byte[] getMac() {
		return mac;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		Utils.writeByteArray(out, encodedAttesterSessionPublicKey);
		evidence.writeExternal(out);
		evidenceSignature.writeExternal(out);
		Utils.writeByteArray(out, mac);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		encodedAttesterSessionPublicKey = Utils.readByteArray(in);
		evidence = new Evidence();
		evidence.readExternal(in);
		evidenceSignature = new SchnorrSignature();
		evidenceSignature.readExternal(in);
		mac = Utils.readByteArray(in);
	}
}
