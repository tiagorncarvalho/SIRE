package sire.serverProxyUtils;

import sire.extensions.Extension;
import sire.extensions.ExtensionType;

import java.io.Serializable;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.TreeMap;

public class AppContext implements Serializable {
    final String id;
    TreeMap<String, DeviceContext> devices;
    HashMap<ExtensionType, Extension> extensions;
    Policy policy;

    public AppContext(String id) {
        this.id = id;
        this.devices = new TreeMap<>();
        this.extensions = new HashMap<>();
    }

    public String getId() {
        return id;
    }

    public DeviceContext getDevice(String deviceId) {
        return this.devices.get(deviceId);
    }

    public void addDevice(String deviceId, DeviceContext device){
        if(this.devices.containsKey(deviceId))
            return;
        else
            this.devices.put(deviceId, device);
    }

    public void removeDevice(String deviceId) {
        this.devices.remove(deviceId);
    }

    public void updateDeviceTimestamp(String deviceId, Instant timestamp) {
        DeviceContext temp = this.devices.get(deviceId);
        temp.setLastPing(timestamp);
        this.devices.put(deviceId, temp);
    }

    public void addExtension(ExtensionType type, Extension extension){
        this.extensions.put(type, extension);
    }

    @Override
    public String toString() {
        return "AppContext{" +
                "id='" + id + '\'' +
                ", devices=" + devices +
                ", extensions=" + extensions +
                ", policy=" + policy +
                '}';
    }

    public Extension getExtension(ExtensionType type) {
        return extensions.get(type);
    }
}
