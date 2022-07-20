package sire.membership;

import sire.api.MembershipInterface;
import sire.coordination.ExtensionManager;
import sire.coordination.ExtensionType;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class MembershipManager implements MembershipInterface {
    private final int timeout = 30;
    private final long certTimeout = 30 * 60000;
    private final Map<String, AppContext> membership;
    private static ExtensionManager extensionManager;

    public MembershipManager() {
        membership = new TreeMap<>();
        extensionManager = ExtensionManager.getInstance();
    }

    @Override
    public void join(String appId, String deviceId, Timestamp timestamp, DeviceContext.DeviceType deviceType) {
        extensionManager.runExtension(appId, ExtensionType.EXT_JOIN, deviceId);
        if(!membership.containsKey(appId))
            membership.put(appId, new AppContext(appId, timeout, certTimeout));
        membership.get(appId).addDevice(deviceId, new DeviceContext(deviceId, timestamp, deviceType));
    }

    @Override
    public void leave(String appId, String deviceId) {
        extensionManager.runExtension(appId, ExtensionType.EXT_LEAVE, deviceId);
        membership.get(appId).removeDevice(deviceId);
    }

    @Override
    public void ping(String appId, String deviceId, Timestamp timestamp) {
        extensionManager.runExtension(appId, ExtensionType.EXT_PING, deviceId);
        membership.get(appId).updateDeviceTimestamp(deviceId, timestamp);
    }

    @Override
    public List<DeviceContext> getView(String appId) {
        extensionManager.runExtension(appId, ExtensionType.EXT_VIEW, "");
        return membership.get(appId).getMembership();
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

    public void setDeviceAsAttested(String appId, String deviceId, byte[] certificate, Timestamp timestamp) {
        membership.get(appId).setDeviceAsAttested(deviceId, certificate, timestamp);
    }

}
