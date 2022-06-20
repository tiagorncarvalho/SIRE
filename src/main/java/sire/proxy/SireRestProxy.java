package sire.proxy;

import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import sire.api.ManagementInterface;
import sire.management.AdminManager;
import sire.attestation.Policy;
import sire.messages.Messages;
import sire.membership.DeviceContext;
import sire.serverProxyUtils.SireException;
import vss.facade.SecretSharingException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.List;

import static sire.messages.ProtoUtils.deserialize;

public class SireRestProxy implements ManagementInterface {
    private final ConfidentialServiceProxy serviceProxy;

    public SireRestProxy(int proxyId) throws SireException {
        try {
            ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
            serviceProxy = new ConfidentialServiceProxy(proxyId, responseHandler);
        } catch (SecretSharingException e) {
            throw new SireException("Failed to contact the distributed verifier", e);
        }
    }

    @Override
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

    @Override
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

    @Override
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

    @Override
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

    @Override
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

    @Override
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

    @Override
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

    @Override
    public List<String> getApps(String admin) {
        return AdminManager.getInstance().getAppsFromAdmin(admin);
    }
}
