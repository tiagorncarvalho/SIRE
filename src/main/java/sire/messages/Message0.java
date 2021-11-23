package sire.messages;

import sire.Utils;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Message0 extends SireMessage {
	private String attesterId; //id
	private byte[] encodedAttesterSessionPublicKey; //Ga

	public Message0() {}

	public Message0(String attesterId, byte[] encodedAttesterSessionPublicKey) {
		this.attesterId = attesterId;
		this.encodedAttesterSessionPublicKey = encodedAttesterSessionPublicKey;
	}

	public String getAttesterId() {
		return attesterId;
	}

	public byte[] getEncodedAttesterSessionPublicKey() {
		return encodedAttesterSessionPublicKey;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeBytes(attesterId);
		Utils.writeByteArray(out, encodedAttesterSessionPublicKey);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		attesterId = in.readLine();
		encodedAttesterSessionPublicKey = Utils.readByteArray(in);
	}
}
