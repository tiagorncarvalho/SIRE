package sire.dummy;

import org.bouncycastle.math.ec.ECPoint;
import sire.messages.Message0;
import sire.messages.Message1;
import sire.messages.Message2;
import sire.messages.Message3;
import sire.protos.ProtoMessage0;
import sire.protos.ProtoMessage1;
import sire.protos.ProtoMessage2;
import sire.protos.ProtoMessage3;
import sire.proxy.SireException;
import sire.proxy.SireProxy;

public class DummyAttester {
    int proxyId;
    SireProxy proxy;

    public DummyAttester (int proxyId) throws SireException {
        proxyId = proxyId;
        proxy = new SireProxy(proxyId);
    }

    public ECPoint getVerifierPublicKey() {
        return proxy.getVerifierPublicKey();
    }

    public Message1 sendMessage0(int attesterId, Message0 message0) {

        return null; //TODO
    }

    public Message3 sendMessage2(int attesterId, Message2 message2) {
        return null; //TODO
    }

    public void close() {
        //TODO
    }
}
