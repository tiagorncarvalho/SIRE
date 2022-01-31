package sire.dummy;

import org.bouncycastle.math.ec.ECPoint;
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
import java.net.Socket;
import java.util.List;


public class DummyAttester {
    int proxyId;
    //SireProxy proxy;
    int port;
    Socket s;
    DataOutputStream dos;
    DataInputStream dis;

    public DummyAttester (int proxyId) throws SireException {
        this.proxyId = proxyId;
        this.port = 2500 + proxyId;
        //this.proxy = new SireProxy(proxyId);
        try {
            this.s = new Socket("localhost", port);
            this.dos = new DataOutputStream(s.getOutputStream());
            this.dis = new DataInputStream(s.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public ECPoint getVerifierPublicKey() {
        //return proxy.getVerifierPublicKey();
        return null;
    }

    //TODO turn attesterId into hash of Ga
    //TODO add sockets?
    public Message1 join(String appId, String attesterId, Message0 message0) throws SireException, IOException, ClassNotFoundException {
        ProtoMessage0 msg0 = ProtoMessage0.newBuilder()
                .setAttesterId(message0.getAttesterId())
                .setAppId(appId)
                .setAttesterPubSesKey(ByteString.copyFrom(message0.getEncodedAttesterSessionPublicKey()))
                .build();


        this.dos.write(msg0.toByteArray());
        byte[] b = this.dis.readAllBytes();
        Object o = deserialize(b);
        ProtoMessage1 msg1 = null;
        if(o instanceof ProtoMessage1)
            msg1 = (ProtoMessage1) o;

        //ProtoMessage1 msg1 = proxy.join(appId, attesterId, msg0);

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
    public Message3 sendMessage2(String attesterId, Message2 message2) throws SireException, IOException, ClassNotFoundException {
        ProtoMessage2 msg2 = ProtoMessage2.newBuilder()
                .setAttesterPubSesKey(ByteString.copyFrom(message2.getEncodedAttesterSessionPublicKey()))
                .setEvidence(evidenceToProto(message2.getEvidence()))
                .setSignatureEvidence(schnorrToProto(message2.getEvidenceSignature()))
                .setMac(ByteString.copyFrom(message2.getMac()))
                .build();

        this.dos.write(msg2.toByteArray());
        byte[] b = this.dis.readAllBytes();
        Object o = deserialize(b);
        ProtoMessage3 msg3 = null;
        if(o instanceof ProtoMessage3)
            msg3 = (ProtoMessage3) o;

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        //ProtoMessage3 msg3 = proxy.processMessage2(attesterId, msg2);

        Message3 result = new Message3(byteStringToByteArray(out, msg3.getIv()),
                byteStringToByteArray(out, msg3.getEncryptedData()));
        out.close();

        return result;
    }



    public void close() throws IOException {
        this.s.close();
        //this.proxy.close();
    }



    public void put(String appId, String key, byte[] value) throws IOException {
        //proxy.put(appId, key, value);
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_PUT)
                .setAppId(appId)
                .setKey(key)
                .setValue(ByteString.copyFrom(value))
                .build();
        this.dos.write(serialize(msg));
    }


    public void delete(String appId, String key) throws IOException {
        //proxy.delete(appId, key);
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_DELETE)
                .setAppId(appId)
                .setKey(key)
                .build();
        this.dos.write(serialize(msg));
    }


    public byte[] getData(String appId, String key) throws IOException, ClassNotFoundException {
        //return proxy.getData(appId, key);
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_GET)
                .setAppId(appId)
                .setKey(key)
                .build();
        this.dos.write(serialize(msg));
        byte[] b = this.dis.readAllBytes();
        Object o = deserialize(b);
        if(o instanceof ProxyResponse) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            return byteStringToByteArray(out,((ProxyResponse) o).getValue());
        }
        return null;
    }


    public List<byte[]> getList(String appId) throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_GET)
                .setAppId(appId)
                .build();
        this.dos.write(serialize(msg));
        byte[] b = this.dis.readAllBytes();
        Object o = deserialize(b);
        if(o instanceof ProxyResponse) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            //return byteStringToByteArray(out,((ProxyResponse) o).getValue());
        }
        return null;
    }


    public void cas(String appId, String key, byte[] oldData, byte[] newData) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_CAS)
                .setAppId(appId)
                .setKey(key)
                .setValue(ByteString.copyFrom(newData))
                .setOldData(ByteString.copyFrom(oldData))
                .build();
        this.dos.write(serialize(msg));
    }

    public void leave(String appId, String deviceId) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.LEAVE)
                .setAppId(appId)
                .setDeviceId(deviceId)
                .build();
        this.dos.write(serialize(msg));
    }

    public void ping(String appId, String deviceId) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.PING)
                .setAppId(appId)
                .setDeviceId(deviceId)
                .build();
        this.dos.write(serialize(msg));
    }

    public AppContext getView(String appId) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.VIEW)
                .setAppId(appId)
                .build();
        this.dos.write(serialize(msg));
        return null;
    }
}
