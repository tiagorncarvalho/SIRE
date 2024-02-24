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
import java.sql.Timestamp;
import java.util.Arrays;

import static sire.messages.ProtoUtils.byteStringToByteArray;

public class VerifierManager {
    SchnorrSignatureScheme signatureScheme;
    private final PolicyManager policyManager;
    private final AttValueStore attValueStore;

    private String failMessage;

    public VerifierManager() throws NoSuchAlgorithmException {
        signatureScheme = new SchnorrSignatureScheme();
        policyManager = PolicyManager.getInstance();
        attValueStore = AttValueStore.getInstance();
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

    public boolean verifyMQTTEvidence(String deviceId, Timestamp ts, Messages.ProtoMQTTEvidence evidence) throws IOException {
        boolean isMrEnclaveValid = Arrays.equals(attValueStore.getMrEnclave(),
                byteStringToByteArray(new ByteArrayOutputStream(),evidence.getMrEnclave()));
        if(!isMrEnclaveValid) {
            failMessage = "MQTT with id " + deviceId + " failed attestation at " + ts + ": MrEnclave invalid";
            System.out.println(failMessage);
            return false;
        }
        boolean isMrSignerValid = Arrays.equals(attValueStore.getMrSigner(),
                byteStringToByteArray(new ByteArrayOutputStream(),evidence.getMrSigner()));
        if(!isMrSignerValid) {
            failMessage = "MQTT with id " + deviceId + " failed attestation at " + ts + ": MrSigner invalid";
            System.out.println(failMessage);
            return false;
        }
        boolean isSecurityVersionValid = evidence.getSecurityVersion() == attValueStore.getSecurityVersion();
        if(!isSecurityVersionValid) {
            failMessage = "MQTT with id " + deviceId + " failed attestation at " + ts + ": security version invalid";
            System.out.println(failMessage);
            return false;
        }
        boolean isProductIdValid = evidence.getProductId() == attValueStore.getProductId();
        if(!isProductIdValid) {
            failMessage = "MQTT with id " + deviceId + " failed attestation at " + ts + ": MrEnclave invalid";
            System.out.println(failMessage);
            return false;
        }
        byte[] hashClaim = attValueStore.getWasmByteCodeHash();
        byte[] computedClaim = computeHash(hashClaim, hexStringToByteArray(evidence.getNonce()));
        byte[] sentCompClaim = byteStringToByteArray(new ByteArrayOutputStream(), evidence.getClaim());
        boolean isClaimValid = Arrays.equals(computedClaim, sentCompClaim);
        if(!isClaimValid) {
            failMessage = "MQTT with id " + deviceId + " failed attestation at " + ts + ": Claim invalid";
            System.out.println(failMessage);
            return false;
        }

        return true;
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

    public String getFailMessage() {
        return failMessage;
    }
}
