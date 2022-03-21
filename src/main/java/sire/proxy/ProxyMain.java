package sire.proxy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import sire.configuration.Extension;
import sire.configuration.Policy;
import sire.serverProxyUtils.DeviceContext;
import sire.serverProxyUtils.SireException;

import java.util.List;

@SpringBootApplication
public class ProxyMain {
    static SireProxy proxy;
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: sire.proxy.ProxyMain <proxy id>");
            System.exit(-1);
        }
        proxy = null;
        try {
            proxy = new SireProxy(Integer.parseInt(args[0]));
        } catch (SireException e) {
            e.printStackTrace();
        }
        SpringApplication.run(ProxyMain.class, args);
        proxy.run();
    }

    @CrossOrigin(origins = "*", allowedHeaders = "*")
    @RestController
    public class ProxyController {

        @PostMapping("/extension")
        public void addExtension(@RequestParam(value = "key") String key, @RequestBody String code) throws SireException {
            if(key == null || key == "")
                throw new SireException("Malformed key");
            String newCode = code.substring(1, code.length() - 1);
            proxy.addExtension(key, newCode);
        }

        @DeleteMapping("/extension")
        public void removeExtension(@RequestParam(value = "key") String key) throws SireException {
            if(key == null || key == "")
                throw new SireException("Malformed key");
            proxy.removeExtension(key);
        }

        @GetMapping("/extension")
        public Extension getExtension(@RequestParam(value = "key") String key) throws SireException {
            if(key == null || key == "")
                throw new SireException("Malformed key");
            return new Extension (proxy.getExtension(key));
        }

        @PostMapping("/policy")
        public void setPolicy(@RequestParam(value = "appId") String appId, @RequestBody String policy) throws SireException {
            if(appId == null || appId == "")
                throw new SireException("Malformed appId");
            proxy.setPolicy(appId, policy, false);
        }

        @DeleteMapping("/policy")
        public void removePolicy(@RequestParam(value = "appId") String appId) throws SireException {
            if(appId == null || appId == "")
                throw new SireException("Malformed appId");
            proxy.deletePolicy(appId);
        }

        @GetMapping("/policy")
        public Policy getPolicy(@RequestParam(value = "appId") String appId) throws SireException {
            if(appId == null || appId == "")
                throw new SireException("Malformed appId");
            return proxy.getPolicy(appId);
        }

        @GetMapping("/view")
        public List<DeviceContext> getView(@RequestParam(value = "appId") String appId) throws SireException {
            if(appId == null || appId == "")
                throw new SireException("Malformed appId");
            return proxy.getView(appId);
        }
    }
}
