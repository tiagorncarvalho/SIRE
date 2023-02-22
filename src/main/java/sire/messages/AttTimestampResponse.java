package sire.messages;

public class AttTimestampResponse {
    String pubKey;
    String timestamp;
    String sigma;
    String signingPublicKey;
    String randomPublicKey;

    public AttTimestampResponse(String pubKey, String timestamp, String sigma, String signingPublicKey, String randomPublicKey) {
        this.pubKey = pubKey;
        this.timestamp = timestamp;
        this.sigma = sigma;
        this.signingPublicKey = signingPublicKey;
        this.randomPublicKey = randomPublicKey;
    }

    public String getPubKey() {
        return pubKey;
    }

    public String getTimestamp() {
        return timestamp;
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
}
