package sire.membership;

import sire.api.MembershipInterface;
import sire.attestation.AttCertificate;
import sire.coordination.ExtensionManager;
import sire.coordination.ExtensionType;

import java.sql.Timestamp;
import java.util.*;

public class MembershipManager implements MembershipInterface {
    private final int timeout = 30;
    private final long certTimeout = 30 * 60000;
    private final Map<String, AppContext> membership;
    private final ExtensionManager extensionManager;
    private final Map<String, AttCertificate> certificates;

    public MembershipManager() {
        membership = new TreeMap<>();
        extensionManager = ExtensionManager.getInstance();
        certificates = new TreeMap<>();
    }

    @Override
    public void join(String appId, String deviceId, Timestamp timestamp, DeviceContext.DeviceType deviceType) {
        if(!membership.containsKey(appId))
            membership.put(appId, new AppContext(appId, timeout, certTimeout));
        extensionManager.runExtension(appId, ExtensionType.EXT_JOIN, deviceId);
        membership.get(appId).addDevice(deviceId, new DeviceContext(deviceId, timestamp, deviceType));
    }

    @Override
    public void join(String appId, String deviceId) {

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
        return membership.get(appId).isDeviceValid(deviceId) && checkCertificate(appId, deviceId);
    }

    /*public void setDeviceAsAttested(String appId, String deviceId, byte[] certificate, Timestamp timestamp) {
        membership.get(appId).setDeviceAsAttested(deviceId, certificate, timestamp);
    }*/

    public void setCertificate (String appId, String deviceId, Timestamp genTime) {
        certificates.put(appId + deviceId, new AttCertificate(appId, deviceId, genTime, new Timestamp(genTime.getTime() + certTimeout)));
    }

    private boolean checkCertificate(String appId, String deviceId) {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        return certificates.get(appId + deviceId).getExpiryTime().before(now);
    }

}
