package sire.messages;

public class RESTRequests {
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

    public class PutRequest {
        String deviceId;
        String key;
        String value;

        public PutRequest(String deviceId, String key, String value) {
            this.deviceId = deviceId;
            this.key = key;
            this.value = value;
        }

        public String getKey() {
            return key;
        }

        public String getValue() {
            return value;
        }

        public String getDeviceId() {
            return deviceId;
        }
    }

    public class preJoinRequest {
        String attesterPubKey;
        String sigma;
        String signingPublicKey;
        String randomPublicKey;

        public preJoinRequest(String attesterPubKey, String sigma, String signingPublicKey, String randomPublicKey) {
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
    }

    public class CasRequest {
        String key;
        String oldValue;
        String newValue;

        public CasRequest(String key, String oldValue, String newValue) {
            this.key = key;
            this.oldValue = oldValue;
            this.newValue = newValue;
        }

        public String getKey() {
            return key;
        }

        public String getOldValue() {
            return oldValue;
        }

        public String getNewValue() {
            return newValue;
        }
    }

}
