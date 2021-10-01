package sire.messages;

import sire.Utils;
import sire.dummy.Evidence;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Message2 extends SireMessage {
	private byte[] attesterPublicSessionKeyParte;
	private Evidence evidence;
	private byte[] evidenceSignature;
	private byte[] mac;

	public Message2() {}

	public Message2(byte[] attesterPublicSessionKeyParte, Evidence evidence,
					byte[] evidenceSignature, byte[] mac) {
		this.attesterPublicSessionKeyParte = attesterPublicSessionKeyParte;
		this.evidence = evidence;
		this.evidenceSignature = evidenceSignature;
		this.mac = mac;
	}

	public byte[] getAttesterPublicSessionKeyParte() {
		return attesterPublicSessionKeyParte;
	}

	public Evidence getEvidence() {
		return evidence;
	}

	public byte[] getEvidenceSignature() {
		return evidenceSignature;
	}

	public byte[] getMac() {
		return mac;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		Utils.writeByteArray(out, attesterPublicSessionKeyParte);
		evidence.writeExternal(out);
		Utils.writeByteArray(out, evidenceSignature);
		Utils.writeByteArray(out, mac);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		attesterPublicSessionKeyParte = Utils.readByteArray(in);
		evidence = new Evidence();
		evidence.readExternal(in);
		evidenceSignature = Utils.readByteArray(in);
		mac = Utils.readByteArray(in);
	}
}
