package sire.proxy;

import sire.protos.Messages;
import sire.schnorr.SchnorrSignature;

/**
 * Interface to be used by the devices to perform the attestation and membership protocols.
 */
public interface OperationalInterface {
    /**
     * Join the system and start the attestation protocol.
     * @param deviceId Id of the device that is joining the system.
     * @param pubSesKey Device's public session key (Ga).
     */
    Messages.ProtoMessage1 join(int deviceId, byte[] pubSesKey, Evidence evidence, SchnorrSignature schnorrSign);

    /**
     * Leave the system.
     * @param deviceId Id of the device that is leaving the system.
     */
    void leave(int deviceId);

    /**
     * Assure the system that the device is still alive.
     * @param deviceId Id of the device.
     */
    void heartbeat(int deviceId);
}
