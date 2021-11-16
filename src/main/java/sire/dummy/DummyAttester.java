package sire.dummy;

import org.bouncycastle.math.ec.ECPoint;
import sire.protos.Messages.*;
import sire.messages.Message0;
import sire.messages.Message1;
import sire.messages.Message2;
import sire.messages.Message3;
import static sire.utils.protoUtils.*;

import sire.proxy.*;
import com.google.protobuf.ByteString;
import sire.schnorr.SchnorrSignature;

import java.io.*;
import java.util.Arrays;
import java.util.List;


public class DummyAttester {
    int proxyId;
    SireProxy proxy;

    public DummyAttester (int proxyId) throws SireException {
        this.proxyId = proxyId;
        this.proxy = new SireProxy(proxyId);
    }

    public ECPoint getVerifierPublicKey() {
        return proxy.getVerifierPublicKey();
    }

    //TODO turn attesterId into hash of Ga
    //TODO add sockets?
    public Message1 sendMessage0(int attesterId, Message0 message0) throws SireException, IOException {
        ProtoMessage0 msg0 = ProtoMessage0.newBuilder()
                .setAttesterId(message0.getAttesterId())
                .setAttesterPubSesKey(ByteString.copyFrom(message0.getEncodedAttesterSessionPublicKey()))
                .build();

        ProtoMessage1 msg1 = proxy.processMessage0(msg0);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Message1 result = new Message1(byteStringToByteArray(out, msg1.getVerifierPubSesKey()),
                byteStringToByteArray(out, msg1.getVerifierPubKey()),
                protoToSchnorr(msg1.getSignatureSessionKeys()),
                byteStringToByteArray(out, msg1.getMac()));
        out.close();

        return result;
    }

    //TODO turn attesterId into hash of Ga
    //TODO add sockets?
    public Message3 sendMessage2(int attesterId, Message2 message2) throws SireException, IOException {
        ProtoMessage2 msg2 = ProtoMessage2.newBuilder()
                .setAttesterPubSesKey(ByteString.copyFrom(message2.getEncodedAttesterSessionPublicKey()))
                .setEvidence(evidenceToProto(message2.getEvidence()))
                .setSignatureEvidence(schnorrToProto(message2.getEvidenceSignature()))
                .setMac(ByteString.copyFrom(message2.getMac()))
                .build();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte [] test = byteStringToByteArray(out, msg2.getMac());
        //System.out.println("Original mac " + Arrays.toString(message2.getMac()) + " Back to ByteArray " + Arrays.toString(test));

        ProtoMessage3 msg3 = proxy.processMessage2(attesterId, msg2);

        Message3 result = new Message3(byteStringToByteArray(out, msg3.getIv()),
                byteStringToByteArray(out, msg3.getEncryptedData()));
        out.close();

        return result;
    }



    public void close() {
        this.proxy.close();
    }



    public void put(byte[] key, byte[] value) {
        proxy.put(key, value);
    }


    public void delete(byte[] key) {
        proxy.delete(key);
    }


    public byte[] getData(byte[] key) {
        return proxy.getData(key);
    }


    public List<byte[]> getList() {
        return proxy.getList();
    }


    public void cas(byte[] key, byte[] oldData, byte[] newData) {
        proxy.cas(key, oldData, newData);
    }
}
