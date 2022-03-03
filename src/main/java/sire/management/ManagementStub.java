package sire.management;

import sire.api.ManagementInterface;
import sire.extensions.ExtensionType;
import sire.protos.Messages;
import sire.serverProxyUtils.Policy;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class ManagementStub implements ManagementInterface {

    int proxyId;
    int port;
    Socket s;
    ObjectOutputStream oos;
    ObjectInputStream ois;


    public ManagementStub (int proxyId) {
        this.proxyId = proxyId;
        this.port = 2500 + proxyId;
        try {
            this.s = new Socket("localhost", this.port);
            this.oos = new ObjectOutputStream(s.getOutputStream());
            this.ois = new ObjectInputStream(s.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void addExtension(String appId, ExtensionType type, String key, String code) {
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(Messages.ProxyMessage.Operation.EXTENSION_ADD)
                .setType(Messages.ProxyMessage.ProtoExtType.values()[type.ordinal()])
                .setKey(key)
                .setCode(code)
                .build();
        try {
            this.oos.writeObject(msg);
        } catch (IOException e) {
            e.printStackTrace();
        }
        //this.proxy.addExtension(appId, type, key, code);
    }

    @Override
    public void removeExtension(String appId, ExtensionType type, String key) {
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(Messages.ProxyMessage.Operation.EXTENSION_REMOVE)
                .setTypeValue(type.ordinal())
                .setKey(key)
                .build();
        try {
            this.oos.writeObject(msg);
        } catch (IOException e) {
            e.printStackTrace();
        }
        //this.proxy.removeExtension(appId, type, key);
    }

    @Override
    public String getExtension(String appId, ExtensionType type, String key) {
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(Messages.ProxyMessage.Operation.EXTENSION_GET)
                .setTypeValue(type.ordinal())
                .setKey(key)
                .build();
        try {
            this.oos.writeObject(msg);
            Object o = this.ois.readObject();
            if(o instanceof Messages.ProxyResponse p && p.getType() == Messages.ProxyResponse.ResponseType.EXTENSION_GET) {
                return p.getExtension();
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void setPolicy(String appId, String policy) {
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(Messages.ProxyMessage.Operation.POLICY_ADD)
                .setPolicy(policy)
                .build();
        try {
            this.oos.writeObject(msg);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void deletePolicy(String appId) {
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(Messages.ProxyMessage.Operation.POLICY_REMOVE)
                .build();
        try {
            this.oos.writeObject(msg);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Policy getPolicy(String appId) {
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(Messages.ProxyMessage.Operation.POLICY_GET)
                .build();
        try {
            this.oos.writeObject(msg);
            Object o = this.ois.readObject();
            if(o instanceof Messages.ProxyResponse p && p.getType() == Messages.ProxyResponse.ResponseType.POLICY_GET) {
                return new Policy(p.getPolicy());
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void close() {
        try {
            this.s.close();
        } catch (IOException e) {
            //e.printStackTrace();
        }
    }
}
