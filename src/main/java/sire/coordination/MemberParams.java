package sire.coordination;

public class MemberParams {
    private final String deviceId;
    private final String appId;

    public MemberParams(String deviceId, String appId) {
        this.deviceId = deviceId;
        this.appId = appId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getAppId() {
        return appId;
    }
}
