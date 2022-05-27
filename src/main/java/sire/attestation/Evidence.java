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
	private byte[] anchor;
	private int waTZVersion;
	private byte[] claim;
	private byte[] encodedAttestationServicePublicKey;

	public Evidence() {}

	public Evidence(byte[] anchor, int waTZVersion, byte[] claim, byte[] encodedAttestationServicePublicKey) {
		this.anchor = anchor;
		this.waTZVersion = waTZVersion;
		this.claim = claim;
		this.encodedAttestationServicePublicKey = encodedAttestationServicePublicKey;
	}

	public byte[] getAnchor() {
		return anchor;
	}

	public int getWaTZVersion() {
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
		ProtoUtils.writeByteArray(out, anchor);
		out.write(waTZVersion);
		ProtoUtils.writeByteArray(out, claim);
		ProtoUtils.writeByteArray(out, encodedAttestationServicePublicKey);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		anchor = ProtoUtils.readByteArray(in);
		waTZVersion = in.readInt();
		claim = ProtoUtils.readByteArray(in);
		encodedAttestationServicePublicKey = ProtoUtils.readByteArray(in);
	}
}
