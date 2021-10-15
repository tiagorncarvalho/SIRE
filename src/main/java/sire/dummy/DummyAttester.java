package sire.dummy;

import org.bouncycastle.math.ec.ECPoint;
import protos.Messages.*;
import sire.messages.Message0;
import sire.messages.Message1;
import sire.messages.Message2;
import sire.messages.Message3;
import sire.proxy.SireException;
import sire.proxy.SireProxy;
import com.google.protobuf.ByteString;

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
        ProtoMessage0 msg0 = ProtoMessage0.newBuilder()
                .setAttesterId(message0.getAttesterId())
                .setAttesterPubSesKey(ByteString.copyFrom(message0.getEncodedAttesterSessionPublicKey()))
                .build();
        proxy.processMessage0(msg0);
        return null; //TODO
    }

    public Message3 sendMessage2(int attesterId, Message2 message2) {
        return null; //TODO
    }

    public void close() {
        //TODO
    }
}
