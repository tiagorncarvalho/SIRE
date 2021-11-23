package sire.interfaces;

import sire.protos.Messages.ProtoMessage0;
import sire.protos.Messages.ProtoMessage1;
import sire.serverProxyUtils.AppContext;
import sire.serverProxyUtils.SireException;

/**
 * Interface to be used by the devices to perform the attestation and membership protocols.
 */
public interface OperationalInterface {
    /**
     * Join the system and start the attestation protocol.
     * @param msg
     */
    ProtoMessage1 join(String appId, String deviceId, ProtoMessage0 msg) throws SireException;

    /**
     * Leave the system.
     * @param deviceId Id of the device that is leaving the system.
     */
    void leave(String appId, String deviceId);

    /**
     *
     * @param appId
     * @param deviceId
     */
    void ping(String appId, String deviceId);

    /**
     *
     * @param appId
     */
    AppContext getView(String appId);
}
