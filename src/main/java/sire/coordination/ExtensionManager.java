package sire.coordination;

import groovy.lang.GroovyShell;
import groovy.lang.Script;
import org.codehaus.groovy.control.CompilationFailedException;
import sire.attestation.Evidence;

import java.util.Map;
import java.util.TreeMap;

public class ExtensionManager {
    private static ExtensionManager instance = null;
    final Map<String, Extension> extensions;
    final GroovyShell sh;

    public ExtensionManager() {
        this.sh = new GroovyShell();
        this.extensions = new TreeMap<>();
        String keyRequest = "app1EXT_PUT";
        String codeRequest = """
                package sire.coordination
                 
                 def runExtension(ExtParams p) {
                     def temp = new int[3]
                     CoordinationManager store = CoordinationManager.getInstance()
                     def laneList = store.get(p.getAppId(), "lanes")
                     String str = p.getKey().charAt(p.getKey().length() - 1)
                     int lane = str as int
                     println(lane)
                     def b = p.getValue()[0]
                 
                     if(b == (1 as byte) && laneList[lane] == (1 as byte))
                         return new ExtParams(p.getAppId(), "lanes", laneList, null)
                 
                     switch(lane) {
                         case 0:
                             temp = [0, 6, 7] as int[]
                             break
                         case 1:
                             temp = [1, 2, 3] as int[]
                             break
                         case 2:
                             temp = [0, 1, 2] as int[]
                             break
                         case 3:
                             temp = [3, 4, 5] as int[]
                             break
                         case 4:
                             temp = [2, 3, 4] as int[]
                             break
                         case 5:
                             temp = [5, 6, 7] as int[]
                             break
                         case 6:
                             temp = [4, 5, 6] as int[]
                             break
                         case 7:
                             temp = [0, 1, 7] as int[]
                             break
                     }
                 
                     for(i in temp) {
                         laneList[i] = b
                     }
                     ExtParams res = new ExtParams(p.getAppId(), "lanes", laneList as byte[], null)
                 
                     return res;
                 }
                """;
        addExtension(keyRequest, codeRequest);
    }

    public static ExtensionManager getInstance() {
        if(instance == null)
            instance = new ExtensionManager();
        return instance;
    }

    public void addExtension(String key, String code) {
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

    public ExtParams runExtension(String appId, ExtensionType type, String key, ExtParams params) {
        String temp;
        if(extensions.containsKey(appId + type.name() + key))
            temp = appId + type.name() + key;
        else if(extensions.containsKey(appId + type.name()))
            temp = appId + type.name();
        else if (extensions.containsKey(appId))
            temp = appId;
        else {
            return params;
        }
        return (ExtParams) extensions.get(temp).getScript().invokeMethod("runExtension", params);
    }

    public void removeExtension(String key) {
        this.extensions.remove(key);
    }

    public boolean runPolicy(String appId, Evidence evidence) {
        if(extensions.containsKey(appId + ExtensionType.EXT_ATTEST)) {
            return (boolean) extensions.get(appId + ExtensionType.EXT_ATTEST).getScript().invokeMethod("verifyEvidence", evidence);
        }

        return true;
    }

    public MemberParams runExtensionMember(String appId, ExtensionType type, String deviceId, MemberParams params) {
        String temp;
        if(extensions.containsKey(appId + type.name() + deviceId))
            temp = appId + type.name() + deviceId;
        else if(extensions.containsKey(appId + type.name()))
            temp = appId + type.name();
        else if (extensions.containsKey(appId))
            temp = appId;
        else {
            return params;
        }
        return (MemberParams) extensions.get(temp).getScript().invokeMethod("runExtension", params);
    }
}
