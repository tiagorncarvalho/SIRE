package sire.utils;

import com.google.protobuf.ByteString;
import sire.extensions.ExtensionType;
import sire.protos.Messages;
import sire.protos.Messages.ProxyMessage.ProtoExtType;
import sire.schnorr.SchnorrSignature;

import java.io.*;

public class ProtoUtils {
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


    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(obj);
        return out.toByteArray();
    }
    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        return is.readObject();
    }

    public static ProtoExtType extTypeToProto (ExtensionType type) {
        switch(type) {
            case EXT_JOIN -> {
                return ProtoExtType.EXT_JOIN;
            }
            case EXT_LEAVE -> {
                return ProtoExtType.EXT_LEAVE;
            }
            case EXT_PING -> {
                return ProtoExtType.EXT_PING;
            }
            case EXT_VIEW -> {
                return ProtoExtType.EXT_VIEW;
            }
            case EXT_PUT -> {
                return ProtoExtType.EXT_PUT;
            }
            case EXT_DEL -> {
                return ProtoExtType.EXT_DEL;
            }
            case EXT_GET -> {
                return ProtoExtType.EXT_GET;
            }
            case EXT_CAS -> {
                return ProtoExtType.EXT_CAS;
            }
            case EXT_LIST -> {
                return ProtoExtType.EXT_LIST;
            }
        }
        return null;
    }

    public static void writeByteArray(ObjectOutput out, byte[] arr) throws IOException {
        out.writeInt(arr == null ? -1 : arr.length);
        if (arr != null)
            out.write(arr);
    }

    public static byte[] readByteArray(ObjectInput in) throws IOException {
        int len = in.readInt();
        if (len > -1) {
            byte[] result = new byte[len];
            in.readFully(result);
            return result;
        }
        return null;
    }
}
