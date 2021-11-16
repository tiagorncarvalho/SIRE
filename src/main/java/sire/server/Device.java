package sire.server;

import java.security.PublicKey;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author robin
 */
public class Device {
	private final int deviceId;
	private final PublicKey devicePublicKey;

	public Device(PublicKey devicePublicKey, int deviceId) {
		this.devicePublicKey = devicePublicKey;
		this.deviceId = deviceId;
	}

	public PublicKey getDevicePublicKey() {
		return devicePublicKey;
	}

	/*public void addApplication(Application application) {
		applications.put(application.getId(), application);
	}

	public Application getApplication(int id) {
		return applications.get(id);
	}*/
}
