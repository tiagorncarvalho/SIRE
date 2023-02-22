package sire.messages;

public class JoinResponse {
    String pubKey;
    String timestamp;
    String hash;
    String sigma;
    String signingPublicKey;
    String randomPublicKey;

    public JoinResponse(String pubKey, String timestamp, String hash, String sigma, String signingPublicKey,
                        String randomPublicKey) {
        this.pubKey = pubKey;
        this.timestamp = timestamp;
        this.hash = hash;
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

    public String getHash() {
        return hash;
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
