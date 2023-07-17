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
                import java.util.ArrayList
                import java.util.Collections
                import java.util.List
                import java.nio.ByteBuffer
                import java.nio.file.Files
                import java.nio.file.Paths
                
                static double euclideanDistance(double[] x, double[] y) {
                    double sum = 0.0;
                    for (int i = 0; i < x.length; i++) {
                        double diff = x[i] - y[i];
                        sum += diff * diff;
                    }
                    Math.sqrt(sum)
                }
                                
                static double[] krum(double[][] weights, int k) {
                    int n = weights.size()
                    println(weights)
                    double[][] distances = new double[n][n]
                    for (int i = 0; i < n; i++) {
                        for (int j = i + 1; j < n; j++) {
                            distances[i][j] = euclideanDistance(weights[i], weights[j])
                            distances[j][i] = distances[i][j]
                        }
                    }
                    List<ScoreIndex> scores = []
                    for (int i = 0; i < n; i++) {
                        double[] d = distances[i]
                        double sum = d.sum()
                        scores.add(new ScoreIndex(sum, i))
                    }
                    int krumIndex = scores[0].index
                    return weights[krumIndex]
                }
                            
                class ScoreIndex implements Comparable<ScoreIndex> {
                    double score
                    int index
                            
                    ScoreIndex(double score, int index) {
                        this.score = score
                        this.index = index
                    }
                            
                    int compareTo(ScoreIndex other) {
                        Double.compare(score, other.score)
                    }
                }
                
                def runExtension(ModelParams p) {
                    double[][] temp = new double[1][1]
                    temp[0] = p.getValue()
                    println(p.getValue())
                    double[] newVal = krum(temp, 2)
                    print(newVal)
                    return new ModelParams(p.getKey(), newVal)
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

    public ModelParams runExtension(String appId, ExtensionType type, String key, ModelParams params) {
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
        return (ModelParams) extensions.get(temp).getScript().invokeMethod("runExtension", params);
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
