package sire.schnorr;

import org.bouncycastle.math.ec.ECPoint;
import vss.secretsharing.Share;

public interface SignatureScheme {
    SSignature computeSignature(byte[] data, ECPoint key);

    boolean verifySignature(byte[] data, SSignature signature);

    SSignature combineSignature(Share...signatureShares);

    boolean partialVerifySignature(byte[] data, Share partialSignature);
}
