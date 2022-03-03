package sire.api;

import sire.extensions.ExtensionType;
import sire.serverProxyUtils.Policy;

/**
 *
 */
public interface ManagementInterface {
    /**
     *
     * @param appId
     * @param type
     * @param key
     * @param code
     */
    void addExtension(String appId, ExtensionType type, String key, String code);

    /**
     *
     * @param appId
     * @param type
     * @param key
     */
    void removeExtension(String appId, ExtensionType type, String key);

    /**
     *
     * @param appId
     * @param type
     * @param key
     * @return
     */
    String getExtension(String appId, ExtensionType type, String key);

    /**
     *
     * @param appId
     * @param policy
     */
    void setPolicy(String appId, String policy);

    /**
     *
     * @param appId
     */
    void deletePolicy(String appId);

    /**
     *
     * @param appId
     * @return
     */
    Policy getPolicy(String appId);
}
