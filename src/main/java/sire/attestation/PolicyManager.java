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


import sire.coordination.ExtensionManager;
import sire.coordination.ExtensionType;

import java.util.HashMap;
import java.util.Map;

public class PolicyManager {
    private final Map<String, Policy> policies;
    private static PolicyManager instance;
    private final ExtensionManager extensionManager = ExtensionManager.getInstance();

    private PolicyManager() {
        this.policies = new HashMap<>();
        String code = "package sire.attestation\ndef verifyEvidence(Evidence e) {\n    ArrayList<byte[]> refValues = [\"measure1\".bytes, \"measure2\".bytes];\n    boolean isClaimValid = false;\n    for(value in refValues) {\n        if(value == e.getClaim())\n            isClaimValid = true;\n    }\n    ArrayList<byte[]> endorsedKeys = [[3, -27, -103, 52, -58, -46, 91, -103, -14, 0, 65, 73, -91, 31, -42, -97, 77,\n                         19, -55, 8, 125, -9, -82, -117, -70, 102, -110, 88, -121, -76, -88, 44, -75] as byte[]];\n    boolean isKeyValid = true;\n    for(key in endorsedKeys) {\n        if(key == e.getPubKey())\n            isKeyValid = true;\n    }\n    String expectedVersion = \"1.0\";\n    return isClaimValid && isKeyValid && expectedVersion.equals(e.getVersion());\n}";
        this.policies.put("app1", new Policy(code, true));
        extensionManager.addExtension("app1" + ExtensionType.EXT_ATTEST, code);
    }

    public static PolicyManager getInstance() {
        if(instance == null)
            instance = new PolicyManager();
        return instance;
    }

    public void setPolicy(String appId, String policy, boolean type) {
        policies.put(appId, new Policy(policy, type));
        if(type)
            extensionManager.addExtension(appId + ExtensionType.EXT_ATTEST, policy);
    }

    public void removePolicy(String appId) {
        policies.put(appId, new Policy());
    }

    public Policy getPolicy(String appId) {
        if(policies.containsKey(appId))
            return policies.get(appId);
        return new Policy();
    }

    public boolean executePolicy(String appId, Evidence evidence) {
        //return extensionManager.runPolicy(appId, claim);
        Policy temp = policies.get(appId);
        if(temp != null) {
            if (temp.getType()) {
                boolean policyResult = extensionManager.runPolicy(appId, evidence);
                return policyResult;
            } else
                return true; //logical policy
        } else
            return true;
    }
}
