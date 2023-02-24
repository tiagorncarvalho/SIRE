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

import java.io.Serializable;
import java.sql.Timestamp;

public class DeviceContext implements Serializable {
    private final String deviceId;
    private Timestamp lastPing;
    private final Timestamp certExpTime;

    public DeviceContext(String deviceId, Timestamp lastPing, Timestamp certExpTime) {
        this.deviceId = deviceId;
        this.lastPing = lastPing;
        this.certExpTime = certExpTime;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public Timestamp getLastPing() {
        return lastPing;
    }

    public void setLastPing(Timestamp lastPing) {
        this.lastPing = lastPing;
    }

    @Override
    public String toString() {
        return "DeviceContext{" +
                "deviceId='" + deviceId + '\'' +
                ", lastPing=" + lastPing +
                ", certExpTime=" + certExpTime +
                '}';
    }

    public Timestamp getCertExpTime() {
        return certExpTime;
    }

    public boolean isCertificateValid() {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        return this.certExpTime.before(now);
    }

    public boolean isTimedout (int timeout) {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        return new Timestamp(this.lastPing.getTime() + (timeout * 1000L)).before(now);
    }

    public boolean isValid(int timeout) {
        return isTimedout(timeout) && isCertificateValid();
    }

    /*public void setAsAttested(byte[] certificate, Timestamp certExpTime) {
        this.certificate = certificate;
        this.certExpTime = certExpTime;
    }*/

    public enum DeviceType {
        CAMERA,
        THERMOMETER,
        RADAR,
        LIDAR,
        MOTIONSENSOR,
        LIGHTSENSOR
    }
}
