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

public class Policy {
    String policy = "NOT DEFINED";
    boolean type; //false = logic expression, true = script

    public Policy(String policy, boolean type) {
        this.policy = policy;
        this.type = type;
    }

    public Policy() {

    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy, boolean type) {
        this.policy = policy;
        this.type = type;
    }

    public boolean getType() {
        return type;
    }

    public void setType(boolean type) {
        this.type = type;
    }
}
