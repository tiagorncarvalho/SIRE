package sire.coordination;

import java.util.*;

public class CoordinationManager {
    private final Map<String, byte[]> storage;
    private final ExtensionManager extensionManager;

    public CoordinationManager() {
        storage = new TreeMap<>();
        extensionManager = ExtensionManager.getInstance();
    }

    public void put(String appId, String key, byte[] value) {
        extensionManager.runExtension(appId, ExtensionType.EXT_PUT, key);
        storage.put(appId + key, value);
    }

    public void remove(String appId, String key) {
        extensionManager.runExtension(appId, ExtensionType.EXT_DEL, key);
        storage.remove(appId + key);
    }

    public byte[] get(String appId, String key) {
        extensionManager.runExtension(appId, ExtensionType.EXT_GET, key);
        return storage.get(appId + key);
    }

    public Collection<byte[]> getValues(String appId) {
        extensionManager.runExtension(appId, ExtensionType.EXT_LIST, "");
        List<byte[]> res = new ArrayList<>();
        for(Map.Entry<String, byte[]> e : storage.entrySet())
            if(e.getKey().startsWith(appId))
                res.add( e.getValue());
        return res;
    }

    public void cas(String appId, String key, byte[] oldValue, byte[] newValue) {
        if(!storage.containsKey(appId))
            return;
        if(Arrays.equals(storage.get(appId + key), oldValue)) {
            extensionManager.runExtension(appId, ExtensionType.EXT_CAS, key);
            storage.put(appId + key, newValue);
        }
    }
}
