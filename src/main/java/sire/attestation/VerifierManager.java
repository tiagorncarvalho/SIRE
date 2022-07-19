package sire.attestation;

import org.bouncycastle.math.ec.ECPoint;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class VerifierManager {
    SchnorrSignatureScheme signatureScheme;
    MessageDigest messageDigest;
    //private final Map<String, List<byte[]>> refValues;
    //private final Map<String, Set<ECPoint>> endorsedKeys;
    private final PolicyManager policyManager;
    //private final String WaTZVersion;


    public VerifierManager() throws NoSuchAlgorithmException {
        signatureScheme = new SchnorrSignatureScheme();
        messageDigest = MessageDigest.getInstance("SHA256");
        /*refValues = new HashMap<>();
        List<byte[]> tempValues =  new ArrayList<>(Arrays.asList(
                "measure1".getBytes(),
                "measure2".getBytes()
        ));
        refValues.put("app1", tempValues);*/
        /*Set<ECPoint> tempKeys = new HashSet<>();
        tempKeys.add(signatureScheme.decodePublicKey(new byte[] {3, -27, -103, 52, -58, -46, 91,
                -103, -14, 0, 65, 73, -91, 31, -42, -97, 77, 19, -55, 8, 125, -9, -82, -117, -70, 102, -110, 88,
                -121, -76, -88, 44, -75}));
        endorsedKeys = new HashMap<>();
        endorsedKeys.put("app1", tempKeys);*/
        //WaTZVersion = "1.0";
        policyManager = new PolicyManager();
    }

    public boolean verifyEvidence(String appId, DeviceEvidence deviceEvidence) {
        Evidence evidence = deviceEvidence.getEvidence();
        ECPoint attesterPublicKey = signatureScheme.decodePublicKey(evidence
                .getEncodedAttestationServicePublicKey());
        /*if (!endorsedKeys.get(appId).contains(attesterPublicKey)) {
            return false;
        }*/

        byte[] signingHash = computeHash(
                evidence.getAnchor(),
                attesterPublicKey.getEncoded(true),
                evidence.getWaTZVersion().getBytes(),
                evidence.getClaim()
        );
        SchnorrSignature evidenceSignature = deviceEvidence.getEvidenceSignature();
        boolean isValidSignature = signatureScheme.verifySignature(
                signingHash,
                attesterPublicKey,
                signatureScheme.decodePublicKey(evidenceSignature.getRandomPublicKey()),
                new BigInteger(evidenceSignature.getSigma())
        );
        if (!isValidSignature)
            return false;

        return policyManager.executePolicy(appId, evidence);
    }

    private byte[] computeHash(byte[]... contents) {
        for (byte[] content : contents) {
            messageDigest.update(content);
        }
        return messageDigest.digest();
    }


    /*private boolean verifyClaim(String appId, byte[] claim) {
        for(byte[] c : refValues.get(appId)) {
            if (Arrays.equals(c, claim))
                return true;
        }
        return false;
    }*/

    public void setPolicy(String appId, String policy, boolean type) {
        policyManager.setPolicy(appId, policy, type);
    }

    public void removePolicy(String appId) {
        policyManager.removePolicy(appId);
    }

    public Policy getPolicy(String appId) {
        return policyManager.getPolicy(appId);
    }
}
