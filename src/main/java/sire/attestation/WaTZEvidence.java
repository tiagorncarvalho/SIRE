package sire.attestation;

public class WaTZEvidence {
    private final Evidence evidence;
    private final byte[] signature;

    public WaTZEvidence(Evidence evidence, byte[] signature) {
        this.evidence = evidence;
        this.signature = signature;
    }

    public Evidence getEvidence() {
        return evidence;
    }

    public byte[] getSignature() {
        return signature;
    }
}
