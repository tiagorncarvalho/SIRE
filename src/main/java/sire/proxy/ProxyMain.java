package sire.proxy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.groovy.template.GroovyTemplateAutoConfiguration;
import org.springframework.web.bind.annotation.*;
import sire.configuration.Extension;
import sire.configuration.Policy;
import sire.serverProxyUtils.DeviceContext;
import sire.serverProxyUtils.SireException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@SpringBootApplication(exclude = {GroovyTemplateAutoConfiguration.class})
public class ProxyMain {
    /*static SireProxy sireProxy;*/
    static SireRestProxy restProxy;
    static ProxyWatz proxyWatz;
    private static List<String> stateUpdates;
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: sire.proxy.ProxyMain <proxy id>");
            System.exit(-1);
        }

        proxyWatz = null;
        /*sireProxy = null;*/
        stateUpdates = new ArrayList<>();
        try {
            int proxyId = Integer.parseInt(args[0]);
            proxyWatz = new ProxyWatz(proxyId, stateUpdates);
            /*sireProxy = new SireProxy(proxyId);*/
            restProxy = new SireRestProxy(proxyId + 1);
        } catch (SireException e) {
            e.printStackTrace();
        }

        SpringApplication app = new SpringApplication(ProxyMain.class);
        app.setDefaultProperties(Collections
                .singletonMap("server.port", "8083"));
        app.run(args);
        //SpringApplication.run(ProxyMain.class, args);
        proxyWatz.run();
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
            return new Extension(restProxy.getExtension(key));
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

        @GetMapping("/state")
        public List<String> getState() {
            List<String> temp = new ArrayList<>(stateUpdates);
            stateUpdates.clear();

            if(temp.size() > 0)
                System.out.println("Sent: " + temp.get(0));

            return temp;
        }
    }
}
