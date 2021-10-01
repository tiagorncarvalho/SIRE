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
	private byte[] attesterPublicSessionKeyParte;

	public Message0() {}

	public Message0(int attesterId, byte[] attesterPublicSessionKeyParte) {
		this.attesterId = attesterId;
		this.attesterPublicSessionKeyParte = attesterPublicSessionKeyParte;
	}

	public int getAttesterId() {
		return attesterId;
	}

	public byte[] getAttesterPublicSessionKeyParte() {
		return attesterPublicSessionKeyParte;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(attesterId);
		Utils.writeByteArray(out, attesterPublicSessionKeyParte);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		attesterId = in.readInt();
		attesterPublicSessionKeyParte = Utils.readByteArray(in);
	}
}
