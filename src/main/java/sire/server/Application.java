package sire.server;

import javax.crypto.SecretKey;

/**
 * @author robin
 */
public class Application {
	private final int id;
	private byte[] codeMeasurement;
	//private SecretKey sessionKey;

	public Application(int id) {
		this.id = id;
	}

	public int getId() {
		return id;
	}

	public byte[] getCodeMeasurement() {
		return codeMeasurement;
	}

	/*public SecretKey getSessionKey() {
		return sessionKey;
	}*/

	public void setCodeMeasurement(byte[] codeMeasurement) {
		this.codeMeasurement = codeMeasurement;
	}

	/*public void setSessionKey(SecretKey sessionKey) {
		this.sessionKey = sessionKey;
	}*/
}
