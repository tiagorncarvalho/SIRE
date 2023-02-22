package sire.messages;

public class JoinRequest {
    String version;
    String claim;
    String pubKey;
    String timestamp;
    String sigma;
    String signingPublicKey;
    String randomPublicKey;
    String attesterPubKey;

    public JoinRequest(String version, String claim, String pubKey, String timestamp, String sigma,
                       String signingPublicKey, String randomPublicKey, String attesterPubKey) {
        this.version = version;
        this.claim = claim;
        this.pubKey = pubKey;
        this.timestamp = timestamp;
        this.sigma = sigma;
        this.signingPublicKey = signingPublicKey;
        this.randomPublicKey = randomPublicKey;
        this.attesterPubKey = attesterPubKey;
    }

    public String getVersion() {
        return version;
    }

    public String getClaim() {
        return claim;
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

    public String getAttesterPubKey() {
        return attesterPubKey;
    }
}
