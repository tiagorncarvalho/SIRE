package sire.avc;

import bftsmart.tom.MessageContext;
import sire.messages.Messages;

public class IntersectionRequest {
    private final MessageContext messageContext;
    private final Messages.ProxyMessage msg;

    public IntersectionRequest(MessageContext messageContext, Messages.ProxyMessage msg) {
        this.messageContext = messageContext;
        this.msg = msg;
    }

    public MessageContext getMessageContext() {
        return messageContext;
    }

    public Messages.ProxyMessage getMsg() {
        return msg;
    }
}
