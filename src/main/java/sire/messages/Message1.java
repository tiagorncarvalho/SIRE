package sire.messages;

import sire.Utils;
import sire.schnorr.SchnorrSignature;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Message1 extends SireMessage {
	private byte[] verifierPublicSessionKey; //Gv
	private byte[] verifierPublicKey; //V
	private SchnorrSignature signatureOfSessionKeys; //Signv(Gv,Ga)
	private byte[] mac; //MAC_Km(content1)

	public Message1() {}

	public Message1(byte[] verifierPublicSessionKey, byte[] verifierPublicKey, SchnorrSignature signatureOfSessionKeys, byte[] mac) {
		this.verifierPublicSessionKey = verifierPublicSessionKey;
		this.verifierPublicKey = verifierPublicKey;
		this.signatureOfSessionKeys = signatureOfSessionKeys;
		this.mac = mac;
	}

	public byte[] getVerifierPublicSessionKey() {
		return verifierPublicSessionKey;
	}

	public byte[] getVerifierPublicKey() {
		return verifierPublicKey;
	}

	public SchnorrSignature getSignatureOfSessionKeys() {
		return signatureOfSessionKeys;
	}

	public byte[] getMac() {
		return mac;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		Utils.writeByteArray(out, verifierPublicSessionKey);
		Utils.writeByteArray(out, verifierPublicKey);
		signatureOfSessionKeys.writeExternal(out);
		Utils.writeByteArray(out, mac);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		verifierPublicSessionKey = Utils.readByteArray(in);
		verifierPublicKey = Utils.readByteArray(in);
		signatureOfSessionKeys = new SchnorrSignature();
		signatureOfSessionKeys.readExternal(in);
		mac = Utils.readByteArray(in);
	}
}
