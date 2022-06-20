package sire.api;

import sire.attestation.Policy;
import sire.membership.DeviceContext;

import java.util.List;

/**
 *
 */
public interface ManagementInterface {
    /**
     *
     * @param key
     * @param code
     */
    void addExtension(String key, String code);

    /**
     *
     * @param key
     */
    void removeExtension(String key);

    /**
     *
     * @param key
     * @return
     */
    String getExtension(String key);

    /**
     *
     * @param appId
     * @param policy
     */
    void setPolicy(String appId, String policy, boolean type);

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

    /**
     *
     * @param appId
     * @return
     */
    List<DeviceContext> getView(String appId);

    /**
     *
     * @param admin
     * @return
     */
    List<String> getApps(String admin);
}
