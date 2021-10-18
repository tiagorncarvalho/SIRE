package sire.utils;

import com.google.protobuf.ByteString;
import sire.protos.Messages;
import sire.proxy.Evidence;
import sire.schnorr.SchnorrSignature;

public class protoUtils {
    public static Messages.ProtoSchnorr schnorrToProto(SchnorrSignature signature) {
        return Messages.ProtoSchnorr.newBuilder()
                .setSigma(ByteString.copyFrom(signature.getSigma()))
                .setSignPubKey(ByteString.copyFrom(signature.getSigningPublicKey()))
                .setRandomPubKey(ByteString.copyFrom(signature.getRandomPublicKey()))
                .build();
    }

    public static SchnorrSignature protoToSchnorr(Messages.ProtoSchnorr sign) {
        return new SchnorrSignature(sign.getSigma().toByteArray(), sign.getSignPubKey().toByteArray(),
                sign.getRandomPubKey().toByteArray());
    }

    public static Evidence protoToEvidence(Messages.ProtoEvidence evidence) {
        return new Evidence (evidence.getAnchor().toByteArray(), evidence.getWatzVersion(),
                evidence.getClaim().toByteArray(), evidence.getServicePubKey().toByteArray());
    }

    public static Messages.ProtoEvidence evidenceToProto(Evidence evidence) {
        return Messages.ProtoEvidence.newBuilder()
                .setAnchor(ByteString.copyFrom(evidence.getAnchor()))
                .setWatzVersion(evidence.getWaTZVersion())
                .setClaim(ByteString.copyFrom(evidence.getClaim()))
                .build();
    }
}
