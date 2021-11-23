package sire.dummy;

import org.bouncycastle.math.ec.ECPoint;
import sire.interfaces.OperationalInterface;
import sire.protos.Messages.*;
import sire.messages.Message0;
import sire.messages.Message1;
import sire.messages.Message2;
import sire.messages.Message3;
import static sire.utils.ProtoUtils.*;

import sire.proxy.*;
import com.google.protobuf.ByteString;
import sire.serverProxyUtils.AppContext;
import sire.serverProxyUtils.SireException;

import java.io.*;
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
    public Message1 join(String appId, String attesterId, Message0 message0) throws SireException, IOException {
        ProtoMessage0 msg0 = ProtoMessage0.newBuilder()
                .setAttesterId(message0.getAttesterId())
                .setAttesterPubSesKey(ByteString.copyFrom(message0.getEncodedAttesterSessionPublicKey()))
                .build();

        ProtoMessage1 msg1 = proxy.join(appId, attesterId, msg0);

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
    public Message3 sendMessage2(String attesterId, Message2 message2) throws SireException, IOException {
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



    public void put(String key, Object value) {
        proxy.put(key, value);
    }


    public void delete(String key) {
        proxy.delete(key);
    }


    public Object getData(String key) {
        return proxy.getData(key);
    }


    public List<Object> getList() {
        return proxy.getList();
    }


    public void cas(String key, Object oldData, Object newData) {
        proxy.cas(key, oldData, newData);
    }

    public void leave(String appId, String deviceId) {
        this.proxy.leave(appId, deviceId);
    }

    public void ping(String appId, String deviceId) {
        this.proxy.ping(appId, deviceId);
    }

    public AppContext getView(String appId) {
        return this.proxy.getView(appId);
    }
}
