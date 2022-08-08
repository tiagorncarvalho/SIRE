package sire.schnorr;

import org.bouncycastle.math.ec.ECPoint;
import vss.secretsharing.VerifiableShare;

public class SchnorrKeyPair {
	private final VerifiableShare privateKeyShare;
	private final ECPoint publicKeyShare;

	public SchnorrKeyPair(VerifiableShare privateKeyShare, ECPoint publicKeyShare) {
		this.privateKeyShare = privateKeyShare;
		this.publicKeyShare = publicKeyShare;
	}

	public VerifiableShare getPrivateKeyShare() {
		return privateKeyShare;
	}

	public ECPoint getPublicKeyShare() {
		return publicKeyShare;
	}


}
