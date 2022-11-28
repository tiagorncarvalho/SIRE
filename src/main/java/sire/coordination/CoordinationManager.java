package sire.coordination;

import java.util.*;

public class CoordinationManager {
    private final Map<String, byte[]> storage;
    private final ExtensionManager extensionManager;

    public CoordinationManager() {
        storage = new TreeMap<>();
        storage.put("ldn9mm0tmiu89jo15s3tojer07keq91higztjvfoq5ic12fl6tkh5q17lyijgemtxud4gn59ca0bszjh9td1cankw9",
                "wwehfuq652ru0ibdr79eddqmwmhpmcjfz0hx3ihee3gu".getBytes()); //just for benchmarking
        extensionManager = ExtensionManager.getInstance();
    }

    public void put(String appId, String key, byte[] value) {
        ExtParams p = extensionManager.runExtension(appId, ExtensionType.EXT_PUT, key, new ExtParams(key, value, null));
        if(key.contains("model"))
            return;
        storage.put(appId + p.getKey(), p.getValue());
    }

    public void remove(String appId, String key) {
        ExtParams p = extensionManager.runExtension(appId, ExtensionType.EXT_DEL, key, new ExtParams(key, null, null));
        storage.remove(appId + p.getKey());
    }

    public byte[] get(String appId, String key) {
        ExtParams p = extensionManager.runExtension(appId, ExtensionType.EXT_GET, key, new ExtParams(key, null, null));
        System.out.println("Babababbaba");
        return p.getValue();
    }

    public Collection<byte[]> getValues(String appId) {
        extensionManager.runExtension(appId, ExtensionType.EXT_LIST, "", new ExtParams(null, null, null));
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
            ExtParams p = extensionManager.runExtension(appId, ExtensionType.EXT_CAS, key, new ExtParams(key, oldValue, newValue));
            storage.put(appId + p.getKey(), p.getNewValue());
        }
    }
}
