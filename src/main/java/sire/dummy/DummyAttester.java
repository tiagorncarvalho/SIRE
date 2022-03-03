package sire.dummy;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import sire.protos.Messages.*;
import sire.messages.Message0;
import sire.messages.Message1;
import sire.messages.Message2;
import sire.messages.Message3;
import static sire.utils.ProtoUtils.*;

import sire.proxy.*;
import com.google.protobuf.ByteString;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.AppContext;
import sire.serverProxyUtils.DeviceContext;
import sire.serverProxyUtils.SireException;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;


public class DummyAttester {
    int proxyId;
    //SireProxy proxy;
    int port;
    Socket s;
    ObjectOutputStream oos;
    ObjectInputStream ois;
    private final BigInteger order;
    private final ECCurve curve;

    public DummyAttester (int proxyId) throws SireException {
        this.proxyId = proxyId;
        this.port = 2500 + proxyId;
        BigInteger prime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
        BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);

        BigInteger cofactor = prime.divide(order);
        curve = new ECCurve.Fp(prime, a, b, order, cofactor);
        //this.proxy = new SireProxy(proxyId);
        try {
            this.s = new Socket("localhost", port);
            this.oos = new ObjectOutputStream(s.getOutputStream());
            this.ois = new ObjectInputStream(s.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public ECPoint getVerifierPublicKey() throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.GET_VERIFIER_PUBLIC_KEY)
                .build();
        this.oos.writeObject(msg);
        Object o = this.ois.readObject();
        if(o instanceof byte[]) {
            return curve.decodePoint((byte[]) o);
        }
        return null;
    }

    //TODO turn attesterId into hash of Ga
    //TODO add sockets?
    public Message1 join(String appId, Message0 message0) throws SireException, IOException, ClassNotFoundException {
        ProtoMessage0 msg0 = ProtoMessage0.newBuilder()
                .setAttesterId(message0.getAttesterId())
                .setAppId(appId)
                .setAttesterPubSesKey(ByteString.copyFrom(message0.getEncodedAttesterSessionPublicKey()))
                .build();

        System.out.println("Joining!");


        //this.dos.write(msg0.toByteArray());
        this.oos.writeObject(msg0);
        Object o = this.ois.readObject();
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
        System.out.println("Message 1 received!");
        return result;
    }

    //TODO turn attesterId into hash of Ga
    //TODO add sockets?
    public Message3 sendMessage2(String attesterId, Message2 message2) throws IOException, ClassNotFoundException {
        System.out.println("Sending Message 2!");
        ProtoMessage2 msg2 = ProtoMessage2.newBuilder()
                .setAttesterPubSesKey(ByteString.copyFrom(message2.getEncodedAttesterSessionPublicKey()))
                .setEvidence(evidenceToProto(message2.getEvidence()))
                .setSignatureEvidence(schnorrToProto(message2.getEvidenceSignature()))
                .setMac(ByteString.copyFrom(message2.getMac()))
                .setAttesterId(attesterId)
                .build();

/*        this.dos.write(msg2.toByteArray());
        byte[] b = this.dis.readAllBytes();*/
        this.oos.writeObject(msg2);
        Object o = this.ois.readObject();//deserialize(b);
        ProtoMessage3 msg3 = null;
        if(o instanceof ProtoMessage3)
            msg3 = (ProtoMessage3) o;

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        //ProtoMessage3 msg3 = proxy.processMessage2(attesterId, msg2);

        Message3 result = new Message3(byteStringToByteArray(out, msg3.getIv()),
                byteStringToByteArray(out, msg3.getEncryptedData()));
        out.close();

        System.out.println("Message 2 received!");

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
        this.oos.writeObject(msg);
        //this.dos.write(serialize(msg));
    }


    public void delete(String appId, String key) throws IOException {
        //proxy.delete(appId, key);
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_DELETE)
                .setAppId(appId)
                .setKey(key)
                .build();
        this.oos.writeObject(msg);
        //this.dos.write(serialize(msg));
    }


    public byte[] getData(String appId, String key) throws IOException, ClassNotFoundException {
        //return proxy.getData(appId, key);
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_GET)
                .setAppId(appId)
                .setKey(key)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
        //byte[] b = this.dis.readAllBytes();
        Object o = this.ois.readObject();//deserialize(b);
        if(o instanceof ProxyResponse pr) {
            //System.out.println("I'm in!");
            if(pr.getValue().equals(ByteString.EMPTY))
                return null;
            else {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                return byteStringToByteArray(out, pr.getValue());
            }
        }
        return null;
    }


    public List<byte[]> getList(String appId) throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.MAP_LIST)
                .setAppId(appId)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
        //byte[] b = this.dis.readAllBytes();
        Object o = this.ois.readObject();//deserialize(b);
        if(o instanceof ProxyResponse) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            List<ByteString> res = ((ProxyResponse) o).getListList();
            ArrayList<byte[]> tmp = new ArrayList<>();
            //System.out.println("List size: " + res.size());
            for(ByteString b : res)
                tmp.add(byteStringToByteArray(out, b));
            return tmp;
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
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
    }

    public void leave(String appId, String deviceId) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.LEAVE)
                .setAppId(appId)
                .setDeviceId(deviceId)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
    }

    public void ping(String appId, String deviceId) throws IOException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.PING)
                .setAppId(appId)
                .setDeviceId(deviceId)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);
    }

    public List<DeviceContext> getView(String appId) throws IOException, ClassNotFoundException {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.VIEW)
                .setAppId(appId)
                .build();
        //this.dos.write(serialize(msg));
        this.oos.writeObject(msg);

        Object o = this.ois.readObject();//deserialize(b);
        if(o instanceof ProxyResponse) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            List<ProxyResponse.ProtoDeviceContext> res = ((ProxyResponse) o).getMembersList();
            ArrayList<DeviceContext> tmp = new ArrayList<>();
            //System.out.println("List size: " + res.size());
            for(ProxyResponse.ProtoDeviceContext d : res)
                tmp.add(new DeviceContext(d.getDeviceId(), new Timestamp(d.getTime().getNanos())));
            return tmp;
            //return byteStringToByteArray(out,((ProxyResponse) o).getValue());
        }
        return null;
    }
}
