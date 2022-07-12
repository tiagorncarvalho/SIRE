package sire.api;

import sire.messages.Messages.ProtoMessage0;
import sire.messages.Messages.ProtoMessage1;
import sire.membership.DeviceContext;
import sire.messages.Messages.ProxyMessage;

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
