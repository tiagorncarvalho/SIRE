package sire.proxy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import sire.attestation.Evidence;
import sire.coordination.Extension;
import sire.attestation.Policy;
import sire.membership.DeviceContext;
import sire.messages.Messages;
import sire.schnorr.SchnorrSignature;
import sire.serverProxyUtils.SireException;

import java.sql.Timestamp;
import java.util.List;

@SpringBootApplication
public class ProxyMain {
    static SocketProxy proxy;
    static RestProxy restProxy;
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: sire.proxy.ProxyMain <proxy id>");
            System.exit(-1);
        }
        proxy = null;
        try {
            int proxyId = Integer.parseInt(args[0]);
            proxy = new SocketProxy(proxyId);
            //restProxy = new RestProxy(proxyId + 1);
        } catch (SireException e) {
            e.printStackTrace();
        }
        //SpringApplication.run(ProxyMain.class, args);
        proxy.run();
    }

    @CrossOrigin(origins = "*", allowedHeaders = "*")
    @RestController
    public static class RestProxyController {

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

        //====================MEMBER====================

        @GetMapping("/timestamp")
        public Messages.ProxyResponse getTimestamp(@RequestParam(value = "appId") String appId, @RequestParam(value = "deviceId") String deviceId,
                                                   byte[] attesterPubKey, byte[] sigma, byte[] signPubKey, byte[] randomPubKey) {
            return restProxy.getTimestamp(appId, deviceId, attesterPubKey, new SchnorrSignature(sigma, signPubKey, randomPubKey));
        }

        @PostMapping("/member")
        public void join(@RequestParam(value = "appId") String appId, String version, byte[] claim,
                         byte[] pubKey, Timestamp ts, byte[] sigma, byte[] signPubKey, byte[] randomPubKey,
                         byte[] attesterPubKey) {
            Evidence e = new Evidence(version, claim, pubKey);
            SchnorrSignature sign = new SchnorrSignature(sigma, signPubKey, randomPubKey);
            restProxy.join(appId, e, ts, sign, attesterPubKey);
        }

        @DeleteMapping("/member")
        public void leave(@RequestParam(value = "appId") String appId, @RequestParam(value = "deviceId") String deviceId) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            else if(deviceId == null || deviceId.equals(""))
                throw new SireException("Malformed deviceId");
            restProxy.leave(appId, deviceId);
        }

        @PutMapping("/ping")
        public void ping(@RequestParam(value = "appId") String appId, @RequestParam(value = "deviceId") String deviceId) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            else if(deviceId == null || deviceId.equals(""))
                throw new SireException("Malformed deviceId");
            restProxy.ping(appId, deviceId);
        }

        //====================MAP====================

        @PutMapping("/map")
        public void mapPut(@RequestParam(value = "appId") String appId, @RequestBody String deviceId,
                           @RequestBody String key, @RequestBody byte[] value) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            else if(deviceId == null || deviceId.equals(""))
                throw new SireException("Malformed deviceId");
            restProxy.put(appId, deviceId, key, value);
        }

        @GetMapping("/map")
        public byte[] mapGet(@RequestParam(value = "appId") String appId, @RequestBody String deviceId,
                             @RequestBody String key) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            else if(deviceId == null || deviceId.equals(""))
                throw new SireException("Malformed deviceId");
            return restProxy.get(appId, deviceId, key);
        }

        @PostMapping("/map")
        public void mapCas(@RequestParam(value = "appId") String appId, @RequestBody String deviceId,
                           @RequestBody String key, @RequestBody byte[] oldValue, @RequestBody byte[] newValue) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            else if(deviceId == null || deviceId.equals(""))
                throw new SireException("Malformed deviceId");
            restProxy.cas(appId, deviceId, key, oldValue, newValue);

        }

        @DeleteMapping("/map")
        public void mapDelete(@RequestParam(value = "appId") String appId, @RequestBody String deviceId,
                              @RequestBody String key) throws SireException {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            else if(deviceId == null || deviceId.equals(""))
                throw new SireException("Malformed deviceId");
            restProxy.delete(appId, deviceId, key);
        }

        @GetMapping("/mapList")
        public List<byte[]> mapList(@RequestParam(value = "appId") String appId, @RequestBody String deviceId) throws SireException  {
            if(appId == null || appId.equals(""))
                throw new SireException("Malformed appId");
            else if(deviceId == null || deviceId.equals(""))
                throw new SireException("Malformed deviceId");
            return restProxy.getList(appId, deviceId);
        }
    }
}
