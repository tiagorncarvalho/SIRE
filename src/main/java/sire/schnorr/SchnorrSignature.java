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

import sire.messages.ProtoUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class SchnorrSignature implements Externalizable {
	private byte[] sigma;
	private byte[] signingPublicKey;
	private byte[] randomPublicKey;

	public SchnorrSignature() {
	}

	public SchnorrSignature(byte[] sigma, byte[] signingPublicKey, byte[] randomPublicKey) {
		this.sigma = sigma;
		this.signingPublicKey = signingPublicKey;
		this.randomPublicKey = randomPublicKey;
	}

	public byte[] getSigma() {
		return sigma;
	}

	public byte[] getSigningPublicKey() {
		return signingPublicKey;
	}

	public byte[] getRandomPublicKey() {
		return randomPublicKey;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		ProtoUtils.writeByteArray(out, sigma);
		ProtoUtils.writeByteArray(out, signingPublicKey);
		ProtoUtils.writeByteArray(out, randomPublicKey);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		sigma = ProtoUtils.readByteArray(in);
		signingPublicKey = ProtoUtils.readByteArray(in);
		randomPublicKey = ProtoUtils.readByteArray(in);
	}
}
