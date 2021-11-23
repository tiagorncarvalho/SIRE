package sire.serverProxyUtils;

import java.io.Serializable;
import java.sql.Timestamp;
import java.time.Instant;

public class DeviceContext implements Serializable {
    private final String deviceId;
    private Instant lastPing;

    public DeviceContext(String deviceId, Instant lastPing) {
        this.deviceId = deviceId;
        this.lastPing = lastPing;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public Instant getLastPing() {
        return lastPing;
    }

    public void setLastPing(Instant lastPing) {
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
