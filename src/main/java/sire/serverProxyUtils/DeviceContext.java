package sire.serverProxyUtils;

import java.io.Serializable;
import java.sql.Timestamp;

public class DeviceContext implements Serializable {
    private final String deviceId;
    private Timestamp lastPing;

    public DeviceContext(String deviceId, Timestamp lastPing) {
        this.deviceId = deviceId;
        this.lastPing = lastPing;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public Timestamp getLastPing() {
        return lastPing;
    }

    public void setLastPing(Timestamp lastPing) {
        this.lastPing = lastPing;
    }

    @Override
    public String toString() {
        return "DeviceContext{" +
                "deviceId='" + deviceId + '\'' +
                ", lastPing=" + lastPing +
                '}';
    }
}
