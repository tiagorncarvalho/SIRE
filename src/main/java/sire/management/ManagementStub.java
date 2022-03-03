package sire.management;

import sire.api.ManagementInterface;
import sire.extensions.Extension;
import sire.extensions.ExtensionType;
import sire.proxy.SireProxy;
import sire.serverProxyUtils.Policy;
import sire.serverProxyUtils.SireException;

public class ManagementStub implements ManagementInterface {

    int proxyId;
    SireProxy proxy;

    public ManagementStub (int proxyId) {
        this.proxyId = proxyId;
        //this.proxy = new SireProxy(proxyId);
        try {
            this.proxy = new SireProxy(proxyId);
        } catch (SireException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void addExtension(String appId, ExtensionType type, String key, String code) {
        //this.proxy.addExtension(appId, type, key, code);
    }

    @Override
    public void removeExtension(String appId, ExtensionType type, String key) {
        //this.proxy.removeExtension(appId, type, key);
    }

    @Override
    public Extension getExtension(String appId, ExtensionType type, String key) {
        //return this.proxy.getExtension(appId, type, key);
        return null;
    }

    @Override
    public void setPolicy(String appId, String policy) {
        //this.proxy.setPolicy(appId, policy);
    }

    @Override
    public void deletePolicy(String appId) {
        //this.proxy.deletePolicy(appId);
    }

    @Override
    public Policy getPolicy(String appId) {
        //return this.proxy.getPolicy(appId);
        return null;
    }

/*    public void close() {
        this.proxy.close();
    }*/
}
