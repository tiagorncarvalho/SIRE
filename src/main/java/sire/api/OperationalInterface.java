package sire.api;

import sire.protos.Messages;
import sire.protos.Messages.ProtoMessage0;
import sire.protos.Messages.ProtoMessage1;
import sire.serverProxyUtils.AppContext;
import sire.serverProxyUtils.SireException;
import sire.protos.Messages.ProxyMessage;

/**
 * Interface to be used by the devices to perform the attestation and membership protocols.
 */
public interface OperationalInterface {
    /**
     * Join the system and start the attestation protocol.
     * @param msg
     */
    ProtoMessage1 join(ProtoMessage0 msg) throws SireException;

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
    AppContext getView(ProxyMessage msg);
}
