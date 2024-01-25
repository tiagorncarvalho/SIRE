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

import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class VerifierManager {
    SchnorrSignatureScheme signatureScheme;
    private final PolicyManager policyManager;

    public VerifierManager() throws NoSuchAlgorithmException {
        signatureScheme = new SchnorrSignatureScheme();
        policyManager = PolicyManager.getInstance();
    }

    public boolean verifyEvidence(String appId, DeviceEvidence deviceEvidence, byte[] ts) throws IOException {
        Evidence evidence = deviceEvidence.getEvidence();
        //ECPoint attesterPublicKey = signatureScheme.decodePublicKey(evidence.getPubKey());

        byte[] signingHash = computeHash(
                //attesterPublicKey.getEncoded(true),
                evidence.getVersion().getBytes(),
                evidence.getClaim(),
                ts,
                appId.getBytes()
        );
        SchnorrSignature evidenceSignature = deviceEvidence.getEvidenceSignature();
        boolean isValidSignature = true;/*signatureScheme.verifySignature(
                signingHash,
                attesterPublicKey,
                signatureScheme.decodePublicKey(evidenceSignature.getRandomPublicKey()),
                new BigInteger(evidenceSignature.getSigma())
        );*/
        if (!isValidSignature)
            return false;

        return policyManager.executePolicy(appId, evidence);
    }

    private static byte[] computeHash(byte[]... contents) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            for (byte[] content : contents) {
                messageDigest.update(content);
            }
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
