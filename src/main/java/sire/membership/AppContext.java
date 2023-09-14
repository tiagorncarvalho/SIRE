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

package sire.membership;

import sire.attestation.Policy;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class AppContext implements Serializable {
    final String id;
    final Map<String, DeviceContext> devices;
    //Policy policy;
    final int timeout;
    final long certTimeout;

    public AppContext(String id, int timeout, long certTimeout) {
        this.id = id;
        this.timeout = timeout;
        this.devices = new TreeMap<>();
        //this.policy = new Policy();
        this.certTimeout = certTimeout;
    }

    public String getId() {
        return id;
    }

    public DeviceContext getDevice(String deviceId) {
        return this.devices.get(deviceId);
    }

    public List<DeviceContext> getMembership() {
        for(Map.Entry<String, DeviceContext> e : devices.entrySet())
            if(e.getValue().isTimedout(this.timeout))
                devices.remove(e.getKey());
        return new ArrayList<>(devices.values());
    }

    public void addDevice(String deviceId, DeviceContext device){
        if (!this.devices.containsKey(deviceId)) {
            this.devices.put(deviceId, device);
        }
    }

    public void removeDevice(String deviceId) {
        this.devices.remove(deviceId);
    }

    public void updateDeviceTimestamp(String deviceId, Timestamp timestamp) {
        DeviceContext temp = this.devices.get(deviceId);
        if(temp != null) {
            temp.setLastPing(timestamp);
            this.devices.put(deviceId, temp);
        }
    }

    @Override
    public String toString() {
        return "AppContext{" +
                "id='" + id + '\'' +
                ", devices=" + devices +
                '}';
    }

/*    public void setPolicy(String policy, boolean type) {
        this.policy.setPolicy(policy, type);
    }

    public void removePolicy() {
        this.policy = new Policy();
    }

    public Policy getPolicy() {
        return policy;
    }*/

    public boolean hasDevice(String deviceId) {
        return devices.containsKey(deviceId);
    }

    /*public void setDeviceAsAttested(String deviceId, byte[] certificate, Timestamp timestamp) {
        this.devices.get(deviceId).setAsAttested(certificate, new Timestamp(timestamp.getTime() + 30 * 60000));
    }*/

    public boolean isDeviceValid(String deviceId) {
        return this.devices.containsKey(deviceId) && this.devices.get(deviceId).isValid(timeout);
    }
}
