package sire.avc;

import sire.messages.Messages;

public class IntersectionRequest {
    private final Messages.ProxyMessage msg;
    private final int proxyId;

    public IntersectionRequest(Messages.ProxyMessage msg, int proxyId) {
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
