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
        String code = "package sire.coordination\n\nstatic double euclideanDistance(double[] x, double[] y) {\n    double sum = 0.0;\n    for (int i = 0; i < x.length; i++) {\n        double diff = x[i] - y[i];\n        sum += diff * diff;\n    }\n    Math.sqrt(sum)\n}\n\nstatic double[] krum(double[][] weights, int k) {\n    int n = weights.size()\n    double[][] distances = new double[n][n]\n    for (int i = 0; i < n; i++) {\n        for (int j = i + 1; j < n; j++) {\n            distances[i][j] = euclideanDistance(weights[i], weights[j])\n            distances[j][i] = distances[i][j]\n        }\n    }\n    List<ScoreIndex> scores = []\n    for (int i = 0; i < n; i++) {\n        double[] d = distances[i]\n        double sum = d.sum()\n        scores.add(new ScoreIndex(sum, i))\n    }\n    int krumIndex = scores[0].index\n    return weights[krumIndex]\n}\n\nclass ScoreIndex implements Comparable<ScoreIndex> {\n    double score\n    int index\n\n    ScoreIndex(double score, int index) {\n        this.score = score\n        this.index = index\n    }\n\n    int compareTo(ScoreIndex other) {\n        Double.compare(score, other.score)\n    }\n}\n\ndef runExtension(ModelParams p) {\n    double[][] temp = new double[1][1]\n    temp[0] = p.getValue()\n    double[] newVal = krum(temp, 2)\n    print(newVal)\n    return new ModelParams(p.getKey(), newVal)\n}";


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
