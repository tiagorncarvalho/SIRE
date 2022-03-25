package sire.configuration;

import groovy.lang.GroovyShell;
import groovy.lang.Script;
import org.codehaus.groovy.control.CompilationFailedException;

import java.util.Map;
import java.util.TreeMap;

public class ExtensionManager {
    Map<String, Extension> extensions;
    GroovyShell sh;
    public ExtensionManager() {
        this.sh = new GroovyShell();
        this.extensions = new TreeMap<>();
    }

    public void addExtension(String key, String code) {
        //System.out.println("============================================= Code: " + code + " =============================================");
        try {
            this.extensions.put(key, new Extension(code, sh.parse(code)));
        } catch (CompilationFailedException e) {
            System.err.println("PARSING ERROR: Extension could not be compiled");
            e.printStackTrace(System.err);
        }
    }

    public Script getExtension(String key) {
        return extensions.containsKey(key) ? extensions.get(key).getScript() : null;
    }

    public String getExtensionCode(String key) {
        return extensions.containsKey(key) ? extensions.get(key).getCode() : null;
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
        //System.out.println("Running extension...");
        extensions.get(temp).getScript().run();
        //System.out.println("Extension ran!");
    }

    public void removeExtension(String key) {
        this.extensions.remove(key);
    }
}
