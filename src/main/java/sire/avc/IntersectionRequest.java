package sire.avc;

import bftsmart.tom.MessageContext;
import sire.messages.Messages;

public class IntersectionRequest {
    private final Messages.ProxyMessage msg;

    public IntersectionRequest(Messages.ProxyMessage msg) {
        this.msg = msg;
    }

    public Messages.ProxyMessage getMsg() {
        return msg;
    }
}
