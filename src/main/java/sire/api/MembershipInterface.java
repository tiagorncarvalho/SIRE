package sire.api;

import sire.messages.Messages.ProtoMessage0;
import sire.messages.Messages.ProtoMessage1;
import sire.serverProxyUtils.DeviceContext;
import sire.messages.Messages.ProxyMessage;

/**
 * Interface to be used by the devices to perform the attestation and membership protocols.
 */
public interface MembershipInterface {
    /**
     * Join the system and start the attestation protocol.
     * @param msg
     */
    ProtoMessage1 join(ProtoMessage0 msg);

    /**
     * Leave the system.
     */
    void leave(ProxyMessage msg);

    /**
     *
     */
    void ping(ProxyMessage msg);

    /**
     *
     */
    DeviceContext[] getView(ProxyMessage msg);
}
