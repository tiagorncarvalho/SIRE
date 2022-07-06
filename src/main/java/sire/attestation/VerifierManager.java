package sire.attestation;

import org.bouncycastle.math.ec.ECPoint;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.SireException;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class VerifierManager {
    SchnorrSignatureScheme signatureScheme;
    MessageDigest messageDigest;
    private final List<byte[]> refValues;
    private final Set<String> endorsedKeys;
    private final int WaTZVersion = 1;


    public VerifierManager() throws NoSuchAlgorithmException {
        signatureScheme = new SchnorrSignatureScheme();
        messageDigest = MessageDigest.getInstance("SHA256");
        refValues =  new ArrayList<>(List.of(
                hexStringToByteArray("D65E90391B43E8943339A55201749B7293E58A6F7876F5158C21E3F62E4D7A83")
        ));
        endorsedKeys = new HashSet<>();
        endorsedKeys.add("0448EEEE81DE28DB3E5D5AFC7D4B7EA4B1AC16A2D7A9978C1F84B4355730643847F7F2CE32434EAB779353748EEE" +
                "64E72976340E805D87C2B6984AA5D12D303FAF");
    }

    public boolean verifyEvidence(DeviceEvidence deviceEvidence) throws SireException {
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

    public void verifyWaTZEvidence(WaTZEvidence deviceEvidence) throws NoSuchAlgorithmException,
            InvalidKeySpecException, SignatureException, NoSuchProviderException, InvalidKeyException, IOException, SireException {
        Evidence evidence = deviceEvidence.getEvidence();
        byte[] attPubKey = evidence.getEncodedAttestationServicePublicKey();
        if(!endorsedKeys.contains(bytesToHex(attPubKey)))
            throw new SireException("Invalid attestation key! </span> Key: " + bytesToHex(attPubKey));
        String attPubKeyX = bytesToHex(Arrays.copyOfRange(attPubKey, 1, 33));
        String attPubKeyY = bytesToHex(Arrays.copyOfRange(attPubKey, 33, attPubKey.length));
        byte[] signature = deviceEvidence.getSignature();
        byte[] signingData = createSigningData(evidence.getAnchor(), evidence.getWaTZVersion(), evidence.getClaim(), attPubKey);
        boolean isValidSignature = signatureScheme.verifyECDSA(signatureScheme.getCurve().createPoint(
                new BigInteger(attPubKeyX, 16), new BigInteger(attPubKeyY, 16)), signature, signingData);
        //System.out.println("IsValidSignature? " + isValidSignature);

        if(!isValidSignature)
            throw new SireException("Invalid signature! </span>");

        if(evidence.getWaTZVersion() != this.WaTZVersion)
            throw new SireException("Wrong WaTZVersion!");

        verifyClaimWatz(evidence.getClaim());
    }

    private byte[] createSigningData(byte[] anchor, int waTZVersion, byte[] claim, byte[] attKey) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.write(anchor);
        dos.writeInt(Integer.reverseBytes(waTZVersion));
        dos.write(claim);
        dos.write(attKey);
        dos.flush();

        return baos.toByteArray();
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

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }


    private boolean verifyClaim(byte[] claim) {
        for(byte[] c : refValues) {
            if (Arrays.equals(c, claim))
                return true;
        }
        return false;
    }

    private void verifyClaimWatz(byte[] claim) throws SireException {
        for(byte[] c : refValues) {
            if (Arrays.equals(c, claim))
                return;
        }
        throw new SireException("Invalid claim!</span> Claim: " + bytesToHex(claim));
    }


    public List<byte[]> getRefValues() {
        return refValues;
    }

    public Set<String> getEndorsedKeys() {
        return endorsedKeys;
    }

    public int getWaTZVersion() {
        return WaTZVersion;
    }
}
