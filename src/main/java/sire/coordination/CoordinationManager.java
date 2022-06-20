package sire.coordination;

import java.util.*;

public class CoordinationManager {
    private final Map<String, Map<String, byte[]>> storage;

    public CoordinationManager() {
        storage = new TreeMap<>();
    }

    public void put(String appId, String key, byte[] value) {
        if(!storage.containsKey(appId))
            storage.put(appId, new TreeMap<>());
        storage.get(appId).put(key, value);
    }

    public void remove(String appId, String key) {
        if(!storage.containsKey(appId))
            return;
        storage.get(appId).remove(key);
    }

    public byte[] get(String appId, String key) {
        if(!storage.containsKey(appId))
            return new byte[0];
        return storage.get(appId).get(key);
    }

    public Collection<byte[]> getValues(String appId) {
        if(!storage.containsKey(appId))
            return Collections.emptyList();
        return storage.get(appId).values();
    }

    public void cas(String appId, String key, byte[] oldValue, byte[] newValue) {
        if(!storage.containsKey(appId))
            return;
        if(Arrays.equals(storage.get(appId).get(key), oldValue))
            storage.get(appId).put(key, newValue);
    }
}
