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

package sire.attestation;

import sire.messages.ProtoUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author Tiago
 */
public class MQTTEvidence implements Externalizable {
	private int securityVersion;
	private int productId;
	private byte[] claim;
	private String nonce;
	private byte[] mrEnclave;
	private byte[] mrSigner;


	public MQTTEvidence() {}

	public MQTTEvidence(int securityVersion, int productId, byte[] claim, String nonce, byte[] mrEnclave, byte[] mrSigner) {
		this.securityVersion = securityVersion;
		this.productId = productId;
		this.claim = claim;
		this.nonce = nonce;
		this.mrEnclave = mrEnclave;
		this.mrSigner = mrSigner;
	}

	public int getSecurityVersion() {
		return securityVersion;
	}

	public int getProductId() {
		return productId;
	}

	public String getNonce() {
		return nonce;
	}

	public byte[] getClaim() {
		return claim;
	}

	public byte[] getMrEnclave() {
		return mrEnclave;
	}

	public byte[] getMrSigner() {
		return mrSigner;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(securityVersion);
		out.writeInt(productId);
		ProtoUtils.writeByteArray(out, claim);
		out.writeUTF(nonce);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		securityVersion = in.readInt();
		productId = in.readInt();
		claim = ProtoUtils.readByteArray(in);
		nonce = in.readUTF();
	}
}
