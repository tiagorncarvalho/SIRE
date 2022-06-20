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
