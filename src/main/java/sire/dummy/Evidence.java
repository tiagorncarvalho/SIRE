package sire.dummy;

import sire.Utils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Evidence implements Externalizable {
	private byte[] anchor;
	private String waTZVersion;
	private byte[] claim;
	private byte[] encodedAttestationServicePublicKey;

	public Evidence() {}

	public Evidence(byte[] anchor, String waTZVersion, byte[] claim, byte[] encodedAttestationServicePublicKey) {
		this.anchor = anchor;
		this.waTZVersion = waTZVersion;
		this.claim = claim;
		this.encodedAttestationServicePublicKey = encodedAttestationServicePublicKey;
	}

	public byte[] getAnchor() {
		return anchor;
	}

	public String getWaTZVersion() {
		return waTZVersion;
	}

	public byte[] getClaim() {
		return claim;
	}

	public byte[] getEncodedAttestationServicePublicKey() {
		return encodedAttestationServicePublicKey;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		Utils.writeByteArray(out, anchor);
		out.writeUTF(waTZVersion);
		Utils.writeByteArray(out, claim);
		Utils.writeByteArray(out, encodedAttestationServicePublicKey);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		anchor = Utils.readByteArray(in);
		waTZVersion = in.readUTF();
		claim = Utils.readByteArray(in);
		encodedAttestationServicePublicKey = Utils.readByteArray(in);
	}
}
