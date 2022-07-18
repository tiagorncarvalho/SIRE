package sire.management;

import sire.api.ManagementInterface;
import sire.messages.Messages;
import sire.attestation.Policy;
import sire.membership.DeviceContext;

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
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setOperation(Messages.ProxyMessage.Operation.EXTENSION_ADD)
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
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setOperation(Messages.ProxyMessage.Operation.EXTENSION_REMOVE)
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
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setOperation(Messages.ProxyMessage.Operation.EXTENSION_GET)
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
    public void setPolicy(String appId, String policy, boolean type) {
        Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                .setAppId(appId)
                .setOperation(Messages.ProxyMessage.Operation.POLICY_ADD)
                .setPolicy(Messages.ProxyMessage.ProtoPolicy.newBuilder()
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
                return new Policy(p.getPolicy(), false);
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
