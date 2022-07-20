package sire.api;

import sire.membership.DeviceContext;

import java.sql.Timestamp;
import java.util.List;

/**
 * Interface to be used by the devices to perform the attestation and membership protocols.
 */
public interface MembershipInterface {
    /**
     * Join the system and start the attestation protocol.
     *
     */
    void join(String appId, String deviceId, Timestamp timestamp, DeviceContext.DeviceType deviceType);

    /**
     * Leave the system.
     */
    void leave(String appId, String deviceId);

    /**
     *
     */
    void ping(String appId, String deviceId, Timestamp timestamp);

    /**
     *
     */
    List<DeviceContext> getView(String appId);
}
