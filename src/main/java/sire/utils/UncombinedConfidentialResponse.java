package sire.utils;

import confidential.ConfidentialExtractedResponse;
import vss.secretsharing.VerifiableShare;

/**
 * @author robin
 */
public class UncombinedConfidentialResponse extends ConfidentialExtractedResponse {
	private final VerifiableShare[][] verifiableShares;
	private final byte[][] sharedData;

	public UncombinedConfidentialResponse(int viewID, byte[] plainData, VerifiableShare[][] verifiableShares, byte[][] sharedData) {
		super(viewID, plainData, null, null);
		this.verifiableShares = verifiableShares;
		this.sharedData = sharedData;
	}

	public VerifiableShare[][] getVerifiableShares() {
		return verifiableShares;
	}

	public byte[][] getSharedData() {
		return sharedData;
	}
}
