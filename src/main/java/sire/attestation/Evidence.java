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

package sire.attestation;

import sire.messages.ProtoUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Evidence implements Externalizable {
    private String version;
    private byte[] claim;
    private byte[] pubKey;

    public Evidence() {}

    public Evidence(String version, byte[] claim, byte[] pubKey) {
        this.version = version;
        this.claim = claim;
        this.pubKey = pubKey;
    }

    public String getVersion() {
        return version;
    }

    public byte[] getClaim() {
        return claim;
    }

    public byte[] getPubKey() {
        return pubKey;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeUTF(version);
        ProtoUtils.writeByteArray(out, claim);
        ProtoUtils.writeByteArray(out, pubKey);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        version = in.readUTF();
        claim = ProtoUtils.readByteArray(in);
        pubKey = ProtoUtils.readByteArray(in);
    }
}