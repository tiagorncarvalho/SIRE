package sire.utils;

import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class cryptoUtils {
    public static byte[] computeMac(CMac macEngine, byte[] secretKey, byte[]... contents) {
        macEngine.init(new KeyParameter(secretKey));
        for (byte[] content : contents) {
            macEngine.update(content, 0, content.length);
        }
        byte[] mac = new byte[macEngine.getMacSize()];
        macEngine.doFinal(mac, 0);
        return mac;
    }
}
