package sire.management;

import sire.api.ManagementInterface;
import sire.attestation.Policy;
import sire.membership.DeviceContext;
import sire.messages.Messages.*;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.List;

public class ManagementStub implements ManagementInterface {

    final int proxyId;
    final int port;
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
    public void addExtension(String key, String code) {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.EXTENSION_ADD)
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
    public void removeExtension(String key) {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.EXTENSION_REMOVE)
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
    public String getExtension(String key) {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setOperation(ProxyMessage.Operation.EXTENSION_GET)
                .setKey(key)
                .build();
        try {
            this.oos.writeObject(msg);
            Object o = this.ois.readObject();
            if(o instanceof ProxyResponse) {
                ProxyResponse res = (ProxyResponse) o;
                if(res.getType() == ProxyResponse.ResponseType.EXTENSION_GET)
                    return res.getExtPolicy();
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void setPolicy(String appId, String policy, boolean type) {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(ProxyMessage.Operation.POLICY_ADD)
                .setPolicy(ProxyMessage.ProtoPolicy.newBuilder()
                        .setPolicy(policy)
                        .setType(type)
                        .build())
                .build();
        try {
            this.oos.writeObject(msg);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void deletePolicy(String appId) {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(ProxyMessage.Operation.POLICY_REMOVE)
                .build();
        try {
            this.oos.writeObject(msg);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Policy getPolicy(String appId) {
        ProxyMessage msg = ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(ProxyMessage.Operation.POLICY_GET)
                .build();
        try {
            this.oos.writeObject(msg);
            Object o = this.ois.readObject();
            if(o instanceof ProxyResponse) {
                ProxyResponse res = (ProxyResponse) o;
                if(res.getType() == ProxyResponse.ResponseType.POLICY_GET)
                    return new Policy(res.getExtPolicy(), false);
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public List<DeviceContext> getView(String appId) {
        return null;
    }

    @Override
    public List<String> getApps(String admin) {
        return AppManager.getInstance().getAppsFromAdmin(admin);
    }

    public void close() {
        try {
            this.s.close();
        } catch (IOException e) {
            //e.printStackTrace();
        }
    }
}
