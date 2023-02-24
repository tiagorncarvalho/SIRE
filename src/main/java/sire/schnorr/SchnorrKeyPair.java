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
