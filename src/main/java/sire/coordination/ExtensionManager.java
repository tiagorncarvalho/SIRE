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
    int nExt = 0;

    public ExtensionManager() {
        this.sh = new GroovyShell();
        this.extensions = new TreeMap<>();
        String code = """
                package sire.coordination
                
                def runExtension(ExtParams p) {
                    println p.getValue();
                    int[] bs = new byte[p.getValue().length]
                    for(int i = 0; i < bs.length; i++)
                        bs[i] = p.getValue()[i] & 0xff
                    println bs
                    def str = "python extensionScript.py --lista " + bs
                    str = str.replace("[", "")
                    str = str.replace("]", "")
                    str = str.replace(",", "")
                    def task = str.execute()
                    def cmdOutputStream = new StringBuffer()
                    task.waitForProcessOutput(cmdOutputStream, System.out)
                    def result = cmdOutputStream.toString()
                    print result
                    return new ExtParams(p.key, result.getBytes())
                    
                }
                """;
        this.extensions.put("app1", new Extension(code, sh.parse(code)));
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
