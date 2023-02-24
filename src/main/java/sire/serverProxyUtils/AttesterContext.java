/*
 * Copyright 2023 Tiago Carvalho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sire.serverProxyUtils;

import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.SecretKey;
import java.math.BigInteger;

/**
 * @author robin
 */
public class AttesterContext {
	private final String attesterId;
	private final ECPoint attesterSessionPublicKey;
	private final BigInteger mySessionPrivateKey;
	private final ECPoint mySessionPublicKey;
	private final SecretKey symmetricEncryptionKey;
	private final byte[] macKey;

	public AttesterContext(String attesterId, BigInteger mySessionPrivateKey, ECPoint mySessionPublicKey,
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

	public String getAttesterId() {
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
