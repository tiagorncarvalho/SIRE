package sire.proxy;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.symmetric.SEED;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import sire.configuration.Extension;
import sire.configuration.Policy;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.DeviceContext;
import sire.serverProxyUtils.SireException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

@SpringBootApplication
public class ProxyMain {
    /*static SireProxy proxy;*/
    static SireRestProxy restProxy;
    static ProxyWatz proxy;
    private static final int AES_KEY_LENGTH = 128;
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        if (args.length < 1) {
            System.out.println("Usage: sire.proxy.ProxyMain <proxy id>");
            System.exit(-1);
        }


        SchnorrSignatureScheme scheme = new SchnorrSignatureScheme();
        ECCurve curve = scheme.getCurve();

        ECPoint attesterPubKey = curve.createPoint(new BigInteger("c42b7207ceb2beecafc310859bcb27e69e1f973dd64a98ccef62efbea05a1a0e", 16),
                new BigInteger("7a9c81f042ecd41f33ecd7e81b17795b2d44229259e36fa37610d563b20fab1b", 16));
        //System.out.println("X: " + attesterPubKey.getAffineXCoord() + " Y: " + attesterPubKey.getAffineYCoord());

        ECPoint verSessionPubKey = curve.createPoint(new BigInteger("971907e89c9c2f3870bedbc8e4eb492b68ba0f3bbd66a712b29098d5f9d55ce6", 16),
                new BigInteger("0310fb91babcd11c629a672bf7a6b6c56d828220eb9a06067339cb501f5ee3ee", 16));

        BigInteger verSessionPrivateKey = new BigInteger("964a3a0393ddf3f04ead3c4be85e5fbe5f3a2323eb36cbfb41c1dd0ed8394bfa", 16);

        ECPoint sharedKey = attesterPubKey.multiply(verSessionPrivateKey);
        sharedKey = sharedKey.normalize();


        CMac cmac = new CMac(new AESEngine());

        byte[] gabx = sharedKey.getXCoord().getEncoded();
        System.out.println("Shared secret: " + bytesToHex(gabx));

        /*int i = 0;
        int j = gabx.length - 1;
        byte tmp;
        while (j > i) {
            tmp = gabx[j];
            gabx[j] = gabx[i];
            gabx[i] = tmp;
            j--;
            i++;
        }

        System.out.println("Little endian: " + bytesToHex(gabx));*/
        cmac.init(new KeyParameter(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
        cmac.update(gabx, 0, gabx.length);
        byte[] out = new byte[cmac.getMacSize()];
        cmac.doFinal(out, 0);

        System.out.println("KDK: " + bytesToHex(out));

        /*int i = 0;
        int j = out.length - 1;
        byte tmp;
        while (j > i) {
            tmp = out[j];
            out[j] = out[i];
            out[i] = tmp;
            j--;
            i++;
        }*/

        CMac cmacKey = new CMac(new AESEngine());
        cmacKey.init(new KeyParameter(out));
        String sequence = "01534d4b00800000";
        byte[] msg = hexStringToByteArray(sequence);
        cmacKey.update(msg, 0, msg.length);
        byte[] macKey = new byte[cmacKey.getMacSize()];
        cmacKey.doFinal(macKey, 0);


        /*byte[] sessionPublicKeysHash = computeHash(verSessionPubKey.getEncoded(true),
                attesterPubKey.getEncoded(true));

        SecretKey symmetricEncryptionKey = createSecretKey(sharedKey.toString().toCharArray(), sessionPublicKeysHash);
        byte[] macKey = symmetricEncryptionKey.getEncoded();*/

        CMac sessionCmac = new CMac(new AESEngine());
        sessionCmac.init(new KeyParameter(out));
        sequence = "01534b00800000";
        msg = hexStringToByteArray(sequence);
        sessionCmac.update(msg, 0, msg.length);
        byte[] sessionKey = new byte[sessionCmac.getMacSize()];
        sessionCmac.doFinal(sessionKey, 0);


        byte[] hardMac = new BigInteger("96E054A70C6F52BC34A2F65260D87983", 16).toByteArray();
        byte[] hardSession = new BigInteger("3E9B243CF24513DA60FED6FB397CE678", 16).toByteArray();

        System.out.println("Shared mac Key: " + bytesToHex(macKey));
        System.out.println("Shared session Key: " + bytesToHex(sessionKey));
        /*System.out.println("Hard shared mac Key: " + Arrays.toString(hardMac));
        System.out.println("Hard shared session Key: " + Arrays.toString(hardSession));*/
        /*proxy = null;
        int proxyId = Integer.parseInt(args[0]);
        proxy = new ProxyWatz(proxyId);
        proxy.run();*/
        //BigInteger sharedKey = agreement.calculateAgreement(new ECPublicKeyParameters(attesterPubKey, param));


        /*sharedKey.normalize();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(loadPrivateKey(verSessionPrivateKey));
        ka.doPhase(loadPublicKey(attesterPubKey), true);
        byte[] sharedKey = ka.generateSecret();*/
    }

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    @CrossOrigin(origins = "*", allowedHeaders = "*")
    @RestController
    public static class ProxyController {

        @PostMapping("/extension")
        public void addExtension(@RequestParam(value = "key") String key, @RequestBody String code) throws SireException {
            if(key == null || key.equals(""))
                throw new SireException("Malformed key");
            String newCode = code.substring(1, code.length() - 1);
            restProxy.addExtension(key, newCode);
        }

        @DeleteMapping("/extension")
        public void removeExtension(@RequestParam(value = "key") String key) throws SireException {
            if(key == null || key.equals(""))
                throw new SireException("Malformed key");
            restProxy.removeExtension(key);
        }

        @GetMapping("/extension")
        public Extension getExtension(@RequestParam(value = "key") String key) throws SireException {
            if(key == null || key.equals(""))
                throw new SireException("Malformed key");
            return new Extension (restProxy.getExtension(key));
        }

        @PostMapping("/policy")
        public void setPolicy(@RequestParam(value = "appId") String appId, @RequestBody String policy) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            restProxy.setPolicy(appId, policy, false);
        }

        @DeleteMapping("/policy")
        public void removePolicy(@RequestParam(value = "appId") String appId) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            restProxy.deletePolicy(appId);
        }

        @GetMapping("/policy")
        public Policy getPolicy(@RequestParam(value = "appId") String appId) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            return restProxy.getPolicy(appId);
        }

        @GetMapping("/view")
        public List<DeviceContext> getView(@RequestParam(value = "appId") String appId) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            return restProxy.getView(appId);
        }

        @GetMapping("/apps")
        public List<String> getApps(@RequestParam(value = "admin") String admin) throws SireException {
            if(admin == null || admin.equals(""))
                throw new SireException("Malformed adminId");
            return restProxy.getApps(admin);
        }
    }
}
