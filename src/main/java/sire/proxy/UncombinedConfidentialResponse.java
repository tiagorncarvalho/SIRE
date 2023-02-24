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

package sire.proxy;

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
