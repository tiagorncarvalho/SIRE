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

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class SchnorrNonceManager {
	private final int tableSize;
	private final SchnorrKeyPair[] nonces;
	private final MessageDigest messageDigest;

	public SchnorrNonceManager(int pid, int threshold, ECCurve curve)
			throws NoSuchAlgorithmException {
		messageDigest = MessageDigest.getInstance("SHA-256");
		String fileSeparator = File.separator;
		String keysDirName = "config" + fileSeparator + "schnorr";
		String publicKeysFileName = keysDirName + fileSeparator + threshold + "_publicKeys.txt";
		String commitmentsFileName = keysDirName + fileSeparator + threshold + "_commitments.txt";
		String shareFileName = keysDirName + fileSeparator + threshold + "_" + pid
				+ "_commitments.txt";

		ECPoint[] publicKeys;
		EllipticCurveCommitment[] commitments;
		Share[] shares;
		try (FileInputStream fis = new FileInputStream(publicKeysFileName);
			 ObjectInput in = new ObjectInputStream(fis)) {
			int nKeys = in.readInt();
			publicKeys = new ECPoint[nKeys];
			for (int i = 0; i < nKeys; i++) {
				int encodedKeySize = in.readInt();
				byte[] encodedKey = new byte[encodedKeySize];
				in.readFully(encodedKey);
				publicKeys[i] = curve.decodePoint(encodedKey);
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		try (FileInputStream fis = new FileInputStream(commitmentsFileName);
			 ObjectInput in = new ObjectInputStream(fis)) {
			int nKeys = in.readInt();
			commitments = new EllipticCurveCommitment[nKeys];
			for (int i = 0; i < nKeys; i++) {
				EllipticCurveCommitment c = new EllipticCurveCommitment(curve);
				c.readExternal(in);
				commitments[i] = c;
			}
		} catch (IOException | ClassNotFoundException e) {
			throw new RuntimeException(e);
		}

		try (FileInputStream fis = new FileInputStream(shareFileName);
			 ObjectInput in = new ObjectInputStream(fis)) {
			int nKeys = in.readInt();
			shares = new Share[nKeys];
			for (int i = 0; i < nKeys; i++) {
				shares[i] = (Share) in.readObject();
			}
		} catch (IOException | ClassNotFoundException e) {
			throw new RuntimeException(e);
		}

		tableSize = shares.length;
		nonces = new SchnorrKeyPair[tableSize];
		for (int i = 0; i < tableSize; i++) {
			VerifiableShare privateKeyVShare = new VerifiableShare(shares[i], commitments[i], null);
			nonces[i] = new SchnorrKeyPair(privateKeyVShare, publicKeys[i]);
		}
	}

	public int getTableSize() {
		return tableSize;
	}

	public SchnorrKeyPair getNonce(byte[]... indexData) {
		for (byte[] indexDatum : indexData) {
			messageDigest.update(indexDatum);
		}
		int index = Math.abs(Arrays.hashCode(messageDigest.digest())) % tableSize;
		return nonces[index];
	}

}
