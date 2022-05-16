package sire.attestation;

import java.util.Arrays;

public class Quote {
    private final byte[] anchor;
    private final int version;
    private final byte[] claimHash;

    private final byte[] attestationKey;
    private final byte[] signature;


    public Quote(byte[] temp) {
        anchor = Arrays.copyOfRange(temp, 0, 32);
        version = Byte.toUnsignedInt(temp[32]);
        claimHash = Arrays.copyOfRange(temp, 36, 68);
        attestationKey = Arrays.copyOfRange(temp, 68, 133);
        signature = Arrays.copyOfRange(temp, 133, 197);
    }

    public byte[] getAnchor() {
        return anchor;
    }

    public int getVersion() {
        return version;
    }

    public byte[] getClaimHash() {
        return claimHash;
    }

    public byte[] getAttestationKey() {
        return attestationKey;
    }

    public byte[] getSignature() {
        return signature;
    }

    @Override
    public String toString() {
        return "Quote{" +
                "anchor=" + Arrays.toString(anchor) +
                ", version=" + version +
                ", claimHash=" + Arrays.toString(claimHash) +
                ", attestationKey=" + Arrays.toString(attestationKey) +
                ", signature=" + Arrays.toString(signature) +
                '}';
    }
}
