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
        String code = """
                package sire.attestation
                                
                def verifyEvidence(Evidence e) {
                    def refValues = ["measure1".bytes, "measure2".bytes]
                    def isClaimValid = false
                    for(value in refValues) {
                        if(value == e.getClaim())
                            isClaimValid = true
                    }
                    def endorsedKeys = [[3, -27, -103, 52, -58, -46, 91, -103, -14, 0, 65, 73, -91, 31, -42, -97,
                                         77, 19, -55, 8, 125, -9, -82, -117, -70, 102, -110, 88, -121, -76, -88, 44, -75] as byte[]]
                    def isKeyValid = false
                    for(key in endorsedKeys) {
                        if(key == e.getEncodedAttestationServicePublicKey())
                            isKeyValid = true
                    }
                    def expectedVersion = "1.0"
                    return isClaimValid && isKeyValid && expectedVersion.equals(e.getWaTZVersion())
                }
                """;
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
                System.out.println(policyResult);
                return policyResult;
            } else
                return true; //TODO logical policy
        } else
            return true;
    }
}
