package sire.extensions;

import groovy.lang.GroovyShell;
import groovy.lang.Script;

import java.util.Map;
import java.util.TreeMap;

public class ExtensionManager {
    Map<String, Extension> extensions;
    GroovyShell sh;
    public ExtensionManager() {
        this.sh = new GroovyShell();
        this.extensions = new TreeMap<>();
    }

    public void addExtension(String appId, ExtensionType type, String key, String code) {
        this.extensions.put(appId + type.name() + key, new Extension(code, sh.parse(code)));

    }

    public Script getExtension(String appId, ExtensionType type, String key) {
        return extensions.get(appId + type.name() + key).getScript();
    }

    public Script getExtension(String appId, ExtensionType type) {
        return extensions.get(appId + type.name()).getScript();
    }

    public void runExtension(String appId, ExtensionType type, String key) {
        String temp;
        if(extensions.containsKey(appId + type.name() + key))
            temp = appId + type.name() + key;
        else if(extensions.containsKey(appId + type.name()))
            temp = appId + type.name();
        else if (extensions.containsKey(appId))
            temp = appId;
        else {
            //System.out.println("Left! " + appId + type.name() + key);
            return;
        }
        System.out.println("Running extension...");
        extensions.get(temp).getScript().run();
        System.out.println("Extension ran!");
    }

    public void removeExtension(String appId, ExtensionType type, String key) {
        this.extensions.remove(appId + type + key);
    }

    public String getExtensionCode(String appId, ExtensionType type, String key) {
        return this.extensions.get(appId + type.name() + key).getCode();
    }

    public String getExtensionCode(String appId, ExtensionType type) {
        return this.extensions.get(appId + type.name()).getCode();
    }

}
