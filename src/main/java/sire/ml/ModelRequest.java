package sire.ml;

import sire.messages.Messages;

public class ModelRequest {
    private final Messages.ProxyMessage msg;
    private final int proxyId;

    public ModelRequest(Messages.ProxyMessage msg, int proxyId) {
        this.msg = msg;
        this.proxyId = proxyId;
    }

    public Messages.ProxyMessage getMsg() {
        return msg;
    }

    public int getProxyId() {
        return proxyId;
    }
}
