package sire.messages;

public class AttTimestampRequest {
    String attesterPubKey;
    String sigma;
    String signingPublicKey;
    String randomPublicKey;

    public AttTimestampRequest(String attesterPubKey, String sigma, String signingPublicKey, String randomPublicKey) {
        this.attesterPubKey = attesterPubKey;
        this.sigma = sigma;
        this.signingPublicKey = signingPublicKey;
        this.randomPublicKey = randomPublicKey;
    }

    public String getAttesterPubKey() {
        return attesterPubKey;
    }

    public String getSigma() {
        return sigma;
    }

    public String getSigningPublicKey() {
        return signingPublicKey;
    }

    public String getRandomPublicKey() {
        return randomPublicKey;
    }

    @Override
    public String toString() {
        return "AttTimestampRequest{" +
                "attesterPubKey='" + attesterPubKey + '\'' +
                ", sigma='" + sigma + '\'' +
                ", signingPublicKey='" + signingPublicKey + '\'' +
                ", randomPublicKey='" + randomPublicKey + '\'' +
                '}';
    }
}
