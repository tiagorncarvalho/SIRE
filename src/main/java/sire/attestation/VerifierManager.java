package sire.attestation;

import org.bouncycastle.math.ec.ECPoint;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class VerifierManager {
    SchnorrSignatureScheme signatureScheme;
    MessageDigest messageDigest;
    private final List<byte[]> refValues;
    private final Set<byte[]> endorsedKeys;
    private final int WaTZVersion = 1;


    public VerifierManager() throws NoSuchAlgorithmException {
        signatureScheme = new SchnorrSignatureScheme();
        messageDigest = MessageDigest.getInstance("SHA256");
        refValues =  new ArrayList<>(List.of(
                hexStringToByteArray("a0053ffe015503d7e240239edff8b8ae1b21fbfce5317d658dbeaa131aabefb0")
        ));
        endorsedKeys = new HashSet<>();
        endorsedKeys.add(hexStringToByteArray("0448eeee81de28db3e5d5afc7d4b7ea4b1ac16a2d7a9978c1f84b4355730643847f7f" +
                "2ce32434eab779353748eee64e72976340e805d87c2b6984aa5d12d303faf"));
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
                ByteBuffer.allocate(4).putInt(evidence.getWaTZVersion()).array(),
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

        return verifyClaim(evidence.getClaim()) && evidence.getWaTZVersion() == this.WaTZVersion;
    }

    public boolean verifyWaTZEvidence(WaTZEvidence deviceEvidence) throws NoSuchAlgorithmException,
            InvalidKeySpecException, SignatureException, NoSuchProviderException, InvalidKeyException {
        Evidence evidence = deviceEvidence.getEvidence();
        byte[] attPubKey = evidence.getEncodedAttestationServicePublicKey();
        byte[] signature = deviceEvidence.getSignature();
        boolean isValidSignature = true; /*signatureScheme.verifyECDSA(signatureScheme.getCurve().createPoint(
                new BigInteger(Arrays.copyOfRange(attPubKey, 0, 33)),
                        new BigInteger(Arrays.copyOfRange(attPubKey, 33, attPubKey.length))),
                signature
        );*/

        if(!isValidSignature)
            return false;

        return verifyClaim(evidence.getClaim()) && evidence.getWaTZVersion() == this.WaTZVersion;
    }

    private byte[] computeHash(byte[]... contents) {
        for (byte[] content : contents) {
            messageDigest.update(content);
        }
        return messageDigest.digest();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }


    private boolean verifyClaim(byte[] claim) {
        for(byte[] c : refValues) {
            if (Arrays.equals(c, claim))
                return true;
        }
        return false;
    }


}
