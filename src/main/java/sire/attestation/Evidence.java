package sire.attestation;

import sire.messages.ProtoUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Evidence implements Externalizable {
	private String version;
	private byte[] claim;
	private byte[] pubKey;

	public Evidence() {}

	public Evidence( String version, byte[] claim, byte[] pubKey) {
		this.version = version;
		this.claim = claim;
		this.pubKey = pubKey;
	}

	public String getVersion() {
		return version;
	}

	public byte[] getClaim() {
		return claim;
	}

	public byte[] getPubKey() {
		return pubKey;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeUTF(version);
		ProtoUtils.writeByteArray(out, claim);
		ProtoUtils.writeByteArray(out, pubKey);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		version = in.readUTF();
		claim = ProtoUtils.readByteArray(in);
		pubKey = ProtoUtils.readByteArray(in);
	}
}
