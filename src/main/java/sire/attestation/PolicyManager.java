package sire.attestation;


import sire.coordination.ExtensionManager;
import sire.coordination.ExtensionType;

import java.util.HashMap;
import java.util.Map;

public class PolicyManager {
    private final Map<String, Policy> policies;
    private final ExtensionManager extensionManager = ExtensionManager.getInstance();

    public PolicyManager() {
        this.policies = new HashMap<>();
    }

    public void setPolicy(String appId, String policy, boolean type) {
        policies.put(appId, new Policy(policy, type));
    }

    public void removePolicy(String appId) {
        policies.put(appId, new Policy());
    }

    public Policy getPolicy(String appId) {
        if(policies.containsKey(appId))
            return policies.get(appId);
        return new Policy();
    }

    public boolean executePolicy(String appId) {
        Policy temp = policies.get(appId);
        if(temp != null) {
            if (temp.getType()) {
                extensionManager.runExtension(appId, ExtensionType.EXT_ATTEST, null);
                return true;
            } else
                return true; //TODO logical policy
        } else
            return true;
    }
}
