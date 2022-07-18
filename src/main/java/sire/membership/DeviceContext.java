package sire.membership;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Arrays;

public class DeviceContext implements Serializable {
    private final String deviceId;
    private Timestamp lastPing;
    private DeviceType deviceType;
    private byte[] certificate;
    private Timestamp certExpTime;

    public DeviceContext(String deviceId, Timestamp lastPing, DeviceType deviceType) {
        this.deviceId = deviceId;
        this.lastPing = lastPing;
        this.deviceType = deviceType;
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
                ", certificate=" + Arrays.toString(certificate) +
                ", certExpTime=" + certExpTime +
                '}';
    }

    public DeviceType getDeviceType() {
        return deviceType;
    }

    public void setDeviceType(DeviceType deviceType) {
        this.deviceType = deviceType;
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public Timestamp getCertExpTime() {
        return certExpTime;
    }

    public boolean isAttested() {
        return certificate != null;
    }

    public boolean isTimedout (int timeout) {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        return new Timestamp(this.lastPing.getTime() + (timeout * 1000L)).before(now);
    }

    public boolean isValid(int timeout) {
        return isTimedout(timeout) && isAttested();
    }

    public void setAsAttested(byte[] certificate, Timestamp certExpTime) {
        this.certificate = certificate;
        this.certExpTime = certExpTime;
    }

    public enum DeviceType {
        CAMERA,
        THERMOMETER,
        RADAR,
        LIDAR,
        MOTIONSENSOR,
        LIGHTSENSOR
    }
}
