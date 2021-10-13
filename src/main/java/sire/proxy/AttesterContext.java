package sire.proxy;

import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.SecretKey;
import java.math.BigInteger;

/**
 * @author robin
 */
public class AttesterContext {
	private final int attesterId;
	private final ECPoint attesterSessionPublicKey;
	private final BigInteger mySessionPrivateKey;
	private final ECPoint mySessionPublicKey;
	private final SecretKey symmetricEncryptionKey;
	private final byte[] macKey;

	public AttesterContext(int attesterId, BigInteger mySessionPrivateKey, ECPoint mySessionPublicKey,
						   ECPoint attesterSessionPublicKey, SecretKey symmetricEncryptionKey, byte[] macKey) {
		this.attesterId = attesterId;
		this.attesterSessionPublicKey = attesterSessionPublicKey;
		this.mySessionPrivateKey = mySessionPrivateKey;
		this.mySessionPublicKey = mySessionPublicKey;
		this.symmetricEncryptionKey = symmetricEncryptionKey;
		this.macKey = macKey;
	}

	public ECPoint getMySessionPublicKey() {
		return mySessionPublicKey;
	}

	public int getAttesterId() {
		return attesterId;
	}

	public ECPoint getAttesterSessionPublicKey() {
		return attesterSessionPublicKey;
	}

	public BigInteger getMySessionPrivateKey() {
		return mySessionPrivateKey;
	}

	public SecretKey getSymmetricEncryptionKey() {
		return symmetricEncryptionKey;
	}

	public byte[] getMacKey() {
		return macKey;
	}
}
