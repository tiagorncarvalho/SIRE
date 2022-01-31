package sire.messages;

import sire.schnorr.SchnorrSignature;
import sire.utils.ProtoUtils;

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
		ProtoUtils.writeByteArray(out, verifierPublicSessionKey);
		ProtoUtils.writeByteArray(out, verifierPublicKey);
		signatureOfSessionKeys.writeExternal(out);
		ProtoUtils.writeByteArray(out, mac);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		verifierPublicSessionKey = ProtoUtils.readByteArray(in);
		verifierPublicKey = ProtoUtils.readByteArray(in);
		signatureOfSessionKeys = new SchnorrSignature();
		signatureOfSessionKeys.readExternal(in);
		mac = ProtoUtils.readByteArray(in);
	}
}
