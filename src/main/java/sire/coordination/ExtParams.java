package sire.coordination;

public class ExtParams {
    private final String appId;
    private final String key;
    private final byte[] value; //stands for oldValue in cas operations
    private final byte[] newValue;

    public ExtParams(String appId, String key, byte[] value, byte[] newValue) {
        this.appId = appId;
        this.key = key;
        this.value = value;
        this.newValue = newValue;
    }

    public String getAppId() {
        return appId;
    }

    public String getKey() {
        return key;
    }

    public byte[] getValue() {
        return value;
    }

    public byte[] getNewValue() {
        return newValue;
    }
}
