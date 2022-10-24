package sire.proxy;

import com.google.protobuf.ByteString;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import sire.management.AppManager;
import sire.attestation.Policy;
import sire.messages.Messages;
import sire.membership.DeviceContext;
import sire.serverProxyUtils.SireException;
import vss.facade.SecretSharingException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import static sire.messages.ProtoUtils.deserialize;

public class RestProxy  {
    private final ConfidentialServiceProxy serviceProxy;

    public RestProxy(int proxyId) throws SireException {
        try {
            ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
            serviceProxy = new ConfidentialServiceProxy(proxyId, responseHandler);
        } catch (SecretSharingException e) {
            throw new SireException("Failed to contact the distributed verifier", e);
        }
    }

    public void addExtension(String key, String code) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.EXTENSION_ADD)
                    .setKey(key)
                    .setCode(code)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }

    public void removeExtension(String key) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.EXTENSION_REMOVE)
                    .setKey(key)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public String getExtension(String key) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.EXTENSION_GET)
                    .setKey(key)
                    .build();
            Response res = serviceProxy.invokeOrdered(msg.toByteArray());

            return (String) deserialize(res.getPainData());
        } catch(SecretSharingException | IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }


    public void setPolicy(String appId, String policy, boolean type) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.POLICY_ADD)
                    .setAppId(appId)
                    .setPolicy(Messages.ProxyMessage.ProtoPolicy.newBuilder()
                            .setType(type)
                            .setPolicy(policy)
                            .build())
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public void deletePolicy(String appId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.POLICY_REMOVE)
                    .setAppId(appId)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public Policy getPolicy(String appId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.POLICY_GET)
                    .setAppId(appId)
                    .build();
            Response res = serviceProxy.invokeOrdered(msg.toByteArray());

            return new Policy((String) deserialize(res.getPainData()), false);
        } catch(SecretSharingException | IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }



    public void join(String appId, String deviceId) {
        //TODO
    }


    public void preJoin(String appId, String deviceId, Timestamp timestamp, DeviceContext.DeviceType deviceType) {
        //TODO
    }


    public void leave(String appId, String deviceId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MEMBERSHIP_LEAVE)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public void ping(String appId, String deviceId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MEMBERSHIP_PING)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public List<DeviceContext> getView(String appId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MEMBERSHIP_VIEW)
                    .setAppId(appId)
                    .build();
            Response res = serviceProxy.invokeOrdered(msg.toByteArray());

            byte[] tmp = res.getPainData();
            if (tmp != null) {
                ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
                ObjectInputStream oin = new ObjectInputStream(bin);
                return (List<DeviceContext>) oin.readObject();
            } else
                return null;
        } catch(SecretSharingException | IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }


    public List<String> getApps(String admin) {
        return AppManager.getInstance().getAppsFromAdmin(admin);
    }


    public void put(String appId, String deviceId, String key, byte[] value) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_PUT)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .setKey(key)
                    .setValue(ByteString.copyFrom(value))
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public void delete(String appId, String deviceId, String key) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_DELETE)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .setKey(key)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public byte[] get(String appId, String deviceId, String key) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_PUT)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .setKey(key)
                    .build();
            return serviceProxy.invokeOrdered(msg.toByteArray()).getPainData();
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
        return null;
    }


    public List<byte[]> getList(String appId, String deviceId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_LIST)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .build();
            byte[] tmp = serviceProxy.invokeOrdered(msg.toByteArray()).getPainData();
            ArrayList<byte[]> res = null;
            if (tmp != null) {
                ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
                ObjectInputStream oin = new ObjectInputStream(bin);
                res = (ArrayList<byte[]>) oin.readObject();
            }
            return res;
        } catch (IOException | ClassNotFoundException | SecretSharingException e) {
            e.printStackTrace();
        }
        return null;
    }


    public void cas(String appId, String deviceId, String key, byte[] oldValue, byte[] newValue) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_PUT)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .setKey(key)
                    .setValue(ByteString.copyFrom(newValue))
                    .setOldData(ByteString.copyFrom(oldValue))
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }
}
