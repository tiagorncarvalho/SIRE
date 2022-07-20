package sire.messages;

import com.google.protobuf.ByteString;
import sire.attestation.Evidence;
import sire.schnorr.SchnorrSignature;
import sire.membership.DeviceContext;

import java.io.*;
import java.nio.charset.StandardCharsets;

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
                .setWatzVersion(evidence.getVersion())
                .setClaim(ByteString.copyFrom(evidence.getClaim()))
                .setServicePubKey(ByteString.copyFrom(evidence.getPubKey()))
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

    public static DeviceContext.DeviceType protoDevToDev(Messages.ProtoDeviceType deviceType) {
        return DeviceContext.DeviceType.values()[deviceType.getNumber()];
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
}
