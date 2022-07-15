package sire.attestation;

import java.sql.Timestamp;

public class AttCertificate {
    private final String deviceId;
    private final String appId;
    private final Timestamp genTime;
    private final Timestamp expiryTime;

    public AttCertificate(String deviceId, String appId, Timestamp genTime, Timestamp expiryTime) {
        this.deviceId = deviceId;
        this.appId = appId;
        this.genTime = genTime;
        this.expiryTime = expiryTime;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getAppId() {
        return appId;
    }

    public Timestamp getGenTime() {
        return genTime;
    }

    public Timestamp getExpiryTime() {
        return expiryTime;
    }
}
