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

import sire.membership.DeviceContext;
import sire.messages.Messages.*;

import java.sql.Timestamp;
import java.util.List;

/**
 * Interface to be used by the devices to perform the attestation and membership protocols.
 */
public interface MembershipInterface {

    void join(ProxyMessage msg0);
    /**
     * Join the system and start the attestation protocol.
     *
     */
    void preJoin(ProxyMessage msg2);

    /**
     * Leave the system.
     */
    void leave(String appId, String deviceId);

    /**
     *
     */
    void ping(String appId, String deviceId, Timestamp timestamp);

    /**
     *
     */
    List<DeviceContext> getView(String appId);
}
