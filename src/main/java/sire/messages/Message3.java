package sire.messages;

/**
 * @author robin
 */
public class Message3 {
	private final byte[] initializationVector;
	private final byte[] encryptedData;

	public Message3(byte[] initializationVector, byte[] encryptedData) {
		this.initializationVector = initializationVector;
		this.encryptedData = encryptedData;
	}

	public byte[] getInitializationVector() {
		return initializationVector;
	}

	public byte[] getEncryptedData() {
		return encryptedData;
	}
}
