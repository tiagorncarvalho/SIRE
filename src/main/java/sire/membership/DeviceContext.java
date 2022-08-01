package sire.membership;

import java.io.Serializable;
import java.sql.Timestamp;

public class DeviceContext implements Serializable {
    private final String deviceId;
    private Timestamp lastPing;
    private final DeviceType deviceType;
    private final Timestamp certExpTime;

    public DeviceContext(String deviceId, Timestamp lastPing, DeviceType deviceType, Timestamp certExpTime) {
        this.deviceId = deviceId;
        this.lastPing = lastPing;
        this.deviceType = deviceType;
        this.certExpTime = certExpTime;
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
                ", deviceType=" + deviceType +
                ", certExpTime=" + certExpTime +
                '}';
    }

    public DeviceType getDeviceType() {
        return deviceType;
    }

    public Timestamp getCertExpTime() {
        return certExpTime;
    }

    public boolean isCertificateValid() {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        return this.certExpTime.before(now);
    }

    public boolean isTimedout (int timeout) {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        return new Timestamp(this.lastPing.getTime() + (timeout * 1000L)).before(now);
    }

    public boolean isValid(int timeout) {
        return isTimedout(timeout) && isCertificateValid();
    }

    /*public void setAsAttested(byte[] certificate, Timestamp certExpTime) {
        this.certificate = certificate;
        this.certExpTime = certExpTime;
    }*/

    public enum DeviceType {
        CAMERA,
        THERMOMETER,
        RADAR,
        LIDAR,
        MOTIONSENSOR,
        LIGHTSENSOR
    }
}
