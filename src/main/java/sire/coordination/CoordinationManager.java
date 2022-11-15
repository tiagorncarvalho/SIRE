package sire.coordination;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.*;

public class CoordinationManager {
    private final Map<String, byte[]> storage;
    private final ExtensionManager extensionManager;
    private static CoordinationManager instance = null;

    public static CoordinationManager getInstance() throws IOException {
        if(instance == null)
            instance = new CoordinationManager();
        return instance;
    }

    private CoordinationManager() throws IOException {
        storage = new TreeMap<>();
        extensionManager = ExtensionManager.getInstance();
        byte[] lanes = new byte[8];
        Arrays.fill(lanes, (byte) 0);
        storage.put("app1lanes", lanes);
        List<ExtParams> reqs = new LinkedList<>();

        /*storage.put("ldn9mm0tmiu89jo15s3tojer07keq91higztjvfoq5ic12fl6tkh5q17lyijgemtxud4gn59ca0bszjh9td1cankw9",
                "wwehfuq652ru0ibdr79eddqmwmhpmcjfz0hx3ihee3gu".getBytes()); //just for benchmarking*/
    }

    public boolean put(String appId, String key, byte[] value) {
        ExtParams p = extensionManager.runExtension(appId, ExtensionType.EXT_PUT, key, new ExtParams(appId, key, value, null, false));
        storage.put(appId + p.getKey(), p.getValue());
        System.out.println(key + " " + Arrays.toString(storage.get(appId + p.getKey())) + " " + value[0] + " " + p.getSuccess());
        return p.getSuccess();
    }

    public void remove(String appId, String key) {
        ExtParams p = extensionManager.runExtension(appId, ExtensionType.EXT_DEL, key, new ExtParams(appId, key, null, null, false));
        storage.remove(appId + p.getKey());
    }

    public byte[] get(String appId, String key) {
        ExtParams p = extensionManager.runExtension(appId, ExtensionType.EXT_GET, key, new ExtParams(appId, key, null, null, false));
        return storage.get(appId + p.getKey());
    }

    public Collection<byte[]> getValues(String appId) {
        extensionManager.runExtension(appId, ExtensionType.EXT_LIST, "", new ExtParams(appId,null, null, null, false));
        List<byte[]> res = new ArrayList<>();
        for(Map.Entry<String, byte[]> e : storage.entrySet())
            if(e.getKey().startsWith(appId))
                res.add(e.getValue());
        return res;
    }

    public void cas(String appId, String key, byte[] oldValue, byte[] newValue) {
        if(!storage.containsKey(appId))
            return;
        if(Arrays.equals(storage.get(appId + key), oldValue)) {
            ExtParams p = extensionManager.runExtension(appId, ExtensionType.EXT_CAS, key, new ExtParams(appId, key, oldValue, newValue, false));
            storage.put(appId + p.getKey(), p.getNewValue());
        }
    }
}
