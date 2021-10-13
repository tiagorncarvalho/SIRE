package sire.messages;

import sire.Utils;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Message0 extends SireMessage {
	private int attesterId;
	private byte[] encodedAttesterSessionPublicKey;

	public Message0() {}

	public Message0(int attesterId, byte[] encodedAttesterSessionPublicKey) {
		this.attesterId = attesterId;
		this.encodedAttesterSessionPublicKey = encodedAttesterSessionPublicKey;
	}

	public int getAttesterId() {
		return attesterId;
	}

	public byte[] getEncodedAttesterSessionPublicKey() {
		return encodedAttesterSessionPublicKey;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(attesterId);
		Utils.writeByteArray(out, encodedAttesterSessionPublicKey);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		attesterId = in.readInt();
		encodedAttesterSessionPublicKey = Utils.readByteArray(in);
	}
}
