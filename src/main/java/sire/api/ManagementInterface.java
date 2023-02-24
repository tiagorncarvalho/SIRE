/*
 * Copyright 2023 Tiago Carvalho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
