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
    private final List<byte[]> refValues;
    private final Set<ECPoint> endorsedKeys;
    private final String WaTZVersion = "1.0";


    public VerifierManager() throws NoSuchAlgorithmException {
        signatureScheme = new SchnorrSignatureScheme();
        messageDigest = MessageDigest.getInstance("SHA256");
        refValues =  new ArrayList<>(Arrays.asList(
                "measure1".getBytes(),
                "measure2".getBytes()
        ));
        endorsedKeys = new HashSet<>();
        endorsedKeys.add(signatureScheme.decodePublicKey(new byte[] {3, -27, -103, 52, -58, -46, 91,
                -103, -14, 0, 65, 73, -91, 31, -42, -97, 77, 19, -55, 8, 125, -9, -82, -117, -70, 102, -110, 88,
                -121, -76, -88, 44, -75}));
    }

    public boolean verifyEvidence(DeviceEvidence deviceEvidence) {
        Evidence evidence = deviceEvidence.getEvidence();
        ECPoint attesterPublicKey = signatureScheme.decodePublicKey(evidence
                .getEncodedAttestationServicePublicKey());
        if (!endorsedKeys.contains(attesterPublicKey)) {
            return false;
        }

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

        return verifyClaim(evidence.getClaim()) && evidence.getWaTZVersion().equals(this.WaTZVersion);
    }

    private byte[] computeHash(byte[]... contents) {
        for (byte[] content : contents) {
            messageDigest.update(content);
        }
        return messageDigest.digest();
    }


    private boolean verifyClaim(byte[] claim) {
        for(byte[] c : refValues) {
            if (Arrays.equals(c, claim))
                return true;
        }
        return false;
    }
}
