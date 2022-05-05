package sire.attestation;

import sire.schnorr.SchnorrSignature;

/**
 * @author robin
 */
public class DeviceEvidence {
	private final Evidence evidence;
	private final SchnorrSignature evidenceSignature;

	public DeviceEvidence(Evidence evidence, SchnorrSignature evidenceSignature) {
		this.evidence = evidence;
		this.evidenceSignature = evidenceSignature;
	}

	public Evidence getEvidence() {
		return evidence;
	}

	public SchnorrSignature getEvidenceSignature() {
		return evidenceSignature;
	}

}
