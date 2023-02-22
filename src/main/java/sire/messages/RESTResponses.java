package sire.messages;

public class RESTResponses {
    public static class preJoinResponse {
        String pubKey;
        String timestamp;
        String sigma;
        String signingPublicKey;
        String randomPublicKey;

        public preJoinResponse(String pubKey, String timestamp, String sigma, String signingPublicKey, String randomPublicKey) {
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

    public static class JoinResponse {
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
}
