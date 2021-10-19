package sire.utils;

import com.google.protobuf.ByteString;
import sire.protos.Messages;
import sire.proxy.Evidence;
import sire.schnorr.SchnorrSignature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class protoUtils {
    public static Messages.ProtoSchnorr schnorrToProto(SchnorrSignature signature) {
        return Messages.ProtoSchnorr.newBuilder()
                .setSigma(ByteString.copyFrom(signature.getSigma()))
                .setSignPubKey(ByteString.copyFrom(signature.getSigningPublicKey()))
                .setRandomPubKey(ByteString.copyFrom(signature.getRandomPublicKey()))
                .build();
    }

    public static SchnorrSignature protoToSchnorr(Messages.ProtoSchnorr sign) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        SchnorrSignature sch = new SchnorrSignature(byteStringToByteArray(out, sign.getSigma()), byteStringToByteArray(out, sign.getSignPubKey()),
                byteStringToByteArray(out,sign.getRandomPubKey()));
        out.close();
        return sch;
    }

    public static Evidence protoToEvidence(Messages.ProtoEvidence evidence) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Evidence evi = new Evidence (byteStringToByteArray(out, evidence.getAnchor()), evidence.getWatzVersion(),
                byteStringToByteArray(out, evidence.getClaim()), byteStringToByteArray(out, evidence.getServicePubKey()));
        out.close();
        return evi;
    }

    public static Messages.ProtoEvidence evidenceToProto(Evidence evidence) {
        return Messages.ProtoEvidence.newBuilder()
                .setAnchor(ByteString.copyFrom(evidence.getAnchor()))
                .setWatzVersion(evidence.getWaTZVersion())
                .setClaim(ByteString.copyFrom(evidence.getClaim()))
                .setServicePubKey(ByteString.copyFrom(evidence.getEncodedAttestationServicePublicKey()))
                .build();
    }

    public static byte[] byteStringToByteArray(ByteArrayOutputStream out, ByteString bytestr) throws IOException {
        out.reset();
        bytestr.writeTo(out);

        return out.toByteArray();
    }
}
