package sire.membership;

import sire.api.MembershipInterface;
import sire.coordination.ExtensionManager;
import sire.coordination.ExtensionType;
import sire.coordination.MemberParams;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class MembershipManager {
    private final int timeout = 30;
    private final long certTimeout = 30 * 60000;
    private final Map<String, AppContext> membership;
    private static ExtensionManager extensionManager;

    public MembershipManager() {
        membership = new TreeMap<>();
        extensionManager = ExtensionManager.getInstance();
    }


    public void join(String appId, String deviceId, Timestamp timestamp, DeviceContext.DeviceType deviceType,
                     byte[] certificate) {
        MemberParams res = extensionManager.runExtensionMember(appId, ExtensionType.EXT_JOIN, deviceId, new MemberParams(appId, deviceId));
        if(!membership.containsKey(appId))
            membership.put(appId, new AppContext(appId, timeout, certTimeout));
        membership.get(res.getAppId()).addDevice(res.getDeviceId(), new DeviceContext(res.getDeviceId(), timestamp, deviceType, certificate,
                new Timestamp(timestamp.getTime() + certTimeout)));
    }


    public void leave(String appId, String deviceId) {
        MemberParams res = extensionManager.runExtensionMember(appId, ExtensionType.EXT_LEAVE, deviceId, new MemberParams(appId, deviceId));
        membership.get(appId).removeDevice(deviceId);
    }


    public void ping(String appId, String deviceId, Timestamp timestamp) {
        MemberParams res = extensionManager.runExtensionMember(appId, ExtensionType.EXT_PING, deviceId, new MemberParams(appId, deviceId));
        membership.get(res.getAppId()).updateDeviceTimestamp(res.getDeviceId(), timestamp);
    }


    public List<DeviceContext> getView(String appId) {
        MemberParams res = extensionManager.runExtensionMember(appId, ExtensionType.EXT_VIEW, "", new MemberParams(appId, null));
        return membership.get(res.getAppId()).getMembership();
    }

    public boolean containsApp(String appId) {
        return membership.containsKey(appId);
    }

    public boolean hasDevice(String appId, String deviceId) {
        return membership.get(appId).hasDevice(deviceId);
    }

    public boolean isDeviceValid(String appId, String deviceId) {
        return membership.get(appId).isDeviceValid(deviceId);
    }

}
