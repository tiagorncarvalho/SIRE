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
import java.util.List;

@SpringBootApplication
public class ProxyMain {
    /*static SireProxy proxy;*/
    static SireRestProxy restProxy;
    static ProxyWatz proxy;
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: sire.proxy.ProxyMain <proxy id>");
            System.exit(-1);
        }

        proxy = null;
        int proxyId = Integer.parseInt(args[0]);
        proxy = new ProxyWatz(proxyId);
        proxy.run();
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
