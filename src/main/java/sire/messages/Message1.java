package sire.messages;

import sire.Utils;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Message1 extends SireMessage {
	private byte[] verifierPublicSessionKeyPart;
	private byte[] verifierPublicKey;
	private byte[] signatureOfSessionKeys;
	private byte[] mac;

	public Message1() {}

	public Message1(byte[] verifierPublicSessionKeyPart, byte[] verifierPublicKey, byte[] signatureOfSessionKeys, byte[] mac) {
		this.verifierPublicSessionKeyPart = verifierPublicSessionKeyPart;
		this.verifierPublicKey = verifierPublicKey;
		this.signatureOfSessionKeys = signatureOfSessionKeys;
		this.mac = mac;
	}

	public byte[] getVerifierPublicSessionKeyPart() {
		return verifierPublicSessionKeyPart;
	}

	public byte[] getVerifierPublicKey() {
		return verifierPublicKey;
	}

	public byte[] getSignatureOfSessionKeys() {
		return signatureOfSessionKeys;
	}

	public byte[] getMac() {
		return mac;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		Utils.writeByteArray(out, verifierPublicSessionKeyPart);
		Utils.writeByteArray(out, verifierPublicKey);
		Utils.writeByteArray(out, signatureOfSessionKeys);
		Utils.writeByteArray(out, mac);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		verifierPublicSessionKeyPart = Utils.readByteArray(in);
		verifierPublicKey = Utils.readByteArray(in);
		signatureOfSessionKeys = Utils.readByteArray(in);
		mac = Utils.readByteArray(in);
	}
}
