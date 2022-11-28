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
        String code = """
                package sire.coordination
                
                def runExtension(ExtParams p) {
                    def str = "python extensionScript.py "
                    if(p.value != null) {
                        final ByteArrayOutputStream os = new ByteArrayOutputStream()
                        os.withCloseable {
                            it << p.getValue()
                        }
                        
                        new File("temp.pt").withOutputStream { stream ->
                            os.writeTo(stream)
                        }
                        str = str + "temp.pt"
                    }
                    //println p.getValue()
                    def task = str.execute()
                    def cmdOutputStream = new StringBuffer()
                    task.waitForProcessOutput(cmdOutputStream, System.out)
                    println cmdOutputStream.toString()
                    
                    ExtParams res = new ExtParams(p.key, new File("model.pt").bytes)
                    /*def str2 = "python extensionScript.py a"
                    def task2 = str2.execute()
                    cmdOutputStream2 = new StringBuffer()
                    task2.waitForProcessOutput(cmdOutputStream2, System.out)
                    println cmdOutputStream2.toString()*/
                    
                    //println "stderr: ${task2.err.text}"
                    //println "result ${task.in.getText()}"
                    
                    
                    return res
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
        System.out.println("Extension time!");
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
