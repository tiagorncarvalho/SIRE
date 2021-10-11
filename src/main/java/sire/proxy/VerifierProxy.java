package sire.proxy;

import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.math.ec.ECPoint;
import sire.Operation;
import sire.messages.Message1;
import sire.messages.Message3;
import sire.schnorr.SchnorrSignatureScheme;
import vss.facade.SecretSharingException;

import java.security.NoSuchAlgorithmException;

/**
 * @author robin
 */
public class VerifierProxy {
	private final ConfidentialServiceProxy serviceProxy;
	private final ECPoint verifierPublicKey;
	private final SchnorrSignatureScheme signatureScheme;

	public VerifierProxy(int proxyId) throws SecretSharingException {
		this.serviceProxy = new ConfidentialServiceProxy(proxyId);
		try {
			this.signatureScheme = new SchnorrSignatureScheme();
		} catch (NoSuchAlgorithmException e) {
			throw new SecretSharingException("Failed to initialize Schnorr signature scheme", e);
		}
		Response response = serviceProxy.invokeOrdered(new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
		this.verifierPublicKey = signatureScheme.decodePublicKey(response.getPainData());
	}

	public ECPoint getVerifierPublicKey() {
		return verifierPublicKey;
	}

	public Message1 processMessage0(ECPoint ga) {
		return new Message1();
	}

	public Message3 processMessage2(ECPoint ga, Evidence evidence, byte[] signature) {
		return null;
	}
}
