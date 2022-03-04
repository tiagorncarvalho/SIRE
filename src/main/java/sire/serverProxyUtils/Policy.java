package sire.serverProxyUtils;

public class Policy {
    String policy;
    boolean type; //false = logic expression, true = script

    public Policy(String policy, boolean type) {
        this.policy = policy;
        this.type = type;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy, boolean type) {
        this.policy = policy;
        this.type = type;
    }
}
