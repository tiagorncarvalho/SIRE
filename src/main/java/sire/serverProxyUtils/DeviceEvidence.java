package sire.serverProxyUtils;

import sire.utils.Evidence;
import sire.schnorr.SchnorrSignature;

import java.io.*;

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

	public byte[] serialize() throws SireException {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutput out = new ObjectOutputStream(bos)) {
			evidence.writeExternal(out);
			evidenceSignature.writeExternal(out);
			out.flush();
			bos.flush();
			return bos.toByteArray();
		} catch (IOException e) {
			throw new SireException("Failed to serialize device evidence", e);
		}
	}

	public static DeviceEvidence deserialize(byte[] serializedDeviceEvidence) throws SireException {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedDeviceEvidence);
			 ObjectInput in = new ObjectInputStream(bis)) {
			Evidence evidence = new Evidence();
			evidence.readExternal(in);
			SchnorrSignature evidenceSignature = new SchnorrSignature();
			evidenceSignature.readExternal(in);
			return new DeviceEvidence(evidence, evidenceSignature);
		} catch (IOException e) {
			throw new SireException("Failed to deserialize device evidence", e);
		}
	}
}
