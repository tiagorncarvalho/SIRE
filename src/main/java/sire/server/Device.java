package sire.server;

import java.security.PublicKey;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author robin
 */
public class Device {
	private final PublicKey devicePublicKey;
	private final Map<Integer, Application> applications;

	public Device(PublicKey devicePublicKey) {
		this.devicePublicKey = devicePublicKey;
		this.applications = new TreeMap<>();
	}

	public PublicKey getDevicePublicKey() {
		return devicePublicKey;
	}

	public void addApplication(Application application) {
		applications.put(application.getId(), application);
	}

	public Application getApplication(int id) {
		return applications.get(id);
	}
}
