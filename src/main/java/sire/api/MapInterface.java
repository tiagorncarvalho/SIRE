package sire.api;

import java.util.List;

/**
 * Map interface to communicate with map data structure in the system.
 * Will be used to store data concerning devices, applications, and more, including membership state.
 */
public interface MapInterface {
    /**
     * Adds a new entry to the map. If key already exists, replaces the data.
     * @param key Key to store the information in
     * @param value Information to store
     */
    void put(String appId, String key, byte[] value);

    /**
     * Removes an entry from the map.
     * @param key Key to delete entry
     */
    void delete(String appId, String key);

    /**
     * Gets the data associated with a key from the map. Returns null if non-existent.
     * @param key Key to get the information from
     * @return Data associated with said device.
     */
    byte[] getData(String appId, String key);

    /**
     * Gets a list of all the entries in the system.
     * @return Information from all the entries in the system.
     */
    List<byte[]> getList(String appId);

    /**
     * Compare and swap operation, if data in key is equal to oldData, replaces it with newData.
     * Otherwise, nothing changes.
     * @param key Target key
     * @param oldData Data to compare
     * @param newData Data to replace
     */
    void cas(String appId, String key, byte[] oldData, byte[] newData);
}
