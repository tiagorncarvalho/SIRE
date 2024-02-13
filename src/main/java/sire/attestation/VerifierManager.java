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

import sire.messages.Messages;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static sire.messages.ProtoUtils.byteStringToByteArray;

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

    public boolean verifyMQTTEvidence(Messages.ProtoMQTTEvidence evidence) throws IOException {
        boolean isMrEnclaveValid = Arrays.equals(hexStringToByteArray("DAE0DA2F8A53A0B48F926A3BC048D6A967D47C861986766F8F5AB1C0A8D88E44"),
                byteStringToByteArray(new ByteArrayOutputStream(),evidence.getMrEnclave()));
        boolean isMrSignerValid = Arrays.equals(hexStringToByteArray("83D719E77DEACA1470F6BAF62A4D774303C899DB69020F9C70EE1DFC08C7CE9E"),
                byteStringToByteArray(new ByteArrayOutputStream(),evidence.getMrSigner()));
        boolean isSecurityVersionValid = evidence.getSecurityVersion() == 0;
        boolean isProductIdValid = evidence.getProductId() == 0;
        byte[] hashClaim = hexStringToByteArray("B031E46EFF37EEF7187161353B423C91C82012F026495B40409B3A15DE173343");
        byte[] computedClaim = computeHash(hashClaim, hexStringToByteArray(evidence.getNonce()));
        byte[] sentCompClaim = byteStringToByteArray(new ByteArrayOutputStream(), evidence.getClaim());
        /*System.out.println("mrEnclave? " + isMrEnclaveValid + " isMrSigner? " + isMrSignerValid + " isSec? " +
                isSecurityVersionValid + " isProduct? " + isProductIdValid);
        System.out.println("computed " + Arrays.toString(computedClaim) + "\nsent " + Arrays.toString(sentCompClaim));*/

        return isMrEnclaveValid && isMrSignerValid && isSecurityVersionValid && isProductIdValid && Arrays.equals(computedClaim, sentCompClaim);
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
