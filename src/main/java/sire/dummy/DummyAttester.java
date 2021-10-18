package sire.dummy;

import org.bouncycastle.math.ec.ECPoint;
import sire.protos.Messages.*;
import sire.messages.Message0;
import sire.messages.Message1;
import sire.messages.Message2;
import sire.messages.Message3;
import sire.utils.protoUtils;
import sire.proxy.SireException;
import sire.proxy.SireProxy;
import com.google.protobuf.ByteString;


public class DummyAttester {
    int proxyId;
    SireProxy proxy;

    public DummyAttester (int proxyId) throws SireException {
        this.proxyId = proxyId;
        this.proxy = new SireProxy(proxyId);
    }

    public ECPoint getVerifierPublicKey() {
        return proxy.getVerifierPublicKey();
    }

    public Message1 sendMessage0(int attesterId, Message0 message0) throws SireException {
        ProtoMessage0 msg0 = ProtoMessage0.newBuilder()
                .setAttesterId(message0.getAttesterId())
                .setAttesterPubSesKey(ByteString.copyFrom(message0.getEncodedAttesterSessionPublicKey()))
                .build();

        ProtoMessage1 msg1 = proxy.processMessage0(msg0);

        return new Message1(msg1.getVerifierPubSesKey().toByteArray(), msg1.getVerifierPubKey().toByteArray(),
                protoUtils.protoToSchnorr(msg1.getSignatureSessionKeys()), msg1.getMac().toByteArray());
    }

    public Message3 sendMessage2(int attesterId, Message2 message2) throws SireException {
        ProtoMessage2 msg2 = ProtoMessage2.newBuilder()
                .setAttesterPubSesKey(ByteString.copyFrom(message2.getEncodedAttesterSessionPublicKey()))
                .setEvidence(protoUtils.evidenceToProto(message2.getEvidence()))
                .setSignatureEvidence(protoUtils.schnorrToProto(message2.getEvidenceSignature()))
                .setMac(ByteString.copyFrom(message2.getMac()))
                .build();

        ProtoMessage3 msg3 = proxy.processMessage2(attesterId, msg2);

        return new Message3(msg3.getIv().toByteArray(), msg3.getEncryptedData().toByteArray());
    }

    public void close() {
        this.proxy.close();
    }
}
