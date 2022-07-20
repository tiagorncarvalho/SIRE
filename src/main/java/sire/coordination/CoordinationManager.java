package sire.coordination;

import java.util.*;

public class CoordinationManager {
    private final Map<String, Map<String, byte[]>> storage; //TODO change into a single map
    private final ExtensionManager extensionManager;

    public CoordinationManager() {
        storage = new TreeMap<>();
        extensionManager = ExtensionManager.getInstance();
    }

    public void put(String appId, String key, byte[] value) {
        if(!storage.containsKey(appId))
            storage.put(appId, new TreeMap<>());
        extensionManager.runExtension(appId, ExtensionType.EXT_PUT, key);
        storage.get(appId).put(key, value);
    }

    public void remove(String appId, String key) {
        if(!storage.containsKey(appId))
            return;
        extensionManager.runExtension(appId, ExtensionType.EXT_DEL, key);
        storage.get(appId).remove(key);
    }

    public byte[] get(String appId, String key) {
        if(!storage.containsKey(appId))
            return new byte[0];
        extensionManager.runExtension(appId, ExtensionType.EXT_GET, key);
        return storage.get(appId).get(key);
    }

    public Collection<byte[]> getValues(String appId) {
        if(!storage.containsKey(appId))
            return Collections.emptyList();
        extensionManager.runExtension(appId, ExtensionType.EXT_LIST, "");
        return storage.get(appId).values();
    }

    public void cas(String appId, String key, byte[] oldValue, byte[] newValue) {
        if(!storage.containsKey(appId))
            return;
        if(Arrays.equals(storage.get(appId).get(key), oldValue)) {
            extensionManager.runExtension(appId, ExtensionType.EXT_CAS, key);
            storage.get(appId).put(key, newValue);
        }
    }
}
