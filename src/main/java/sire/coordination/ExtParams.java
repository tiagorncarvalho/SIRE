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

package sire.coordination;

public class ExtParams {
    private final String key;
    private final byte[] value; //stands for newValue in cas operations
    private final byte[] newValue;

    public ExtParams(String key, byte[] value, byte[] newValue) {
        this.key = key;
        this.value = value;
        this.newValue = newValue;
    }

    public String getKey() {
        return key;
    }

    public byte[] getValue() {
        return value;
    }

    public byte[] getNewValue() {
        return newValue;
    }
}
