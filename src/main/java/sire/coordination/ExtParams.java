package sire.coordination;

public class ExtParams {
    private final String appId;
    private final String key;
    private final byte[] value; //stands for oldValue in cas operations
    private final byte[] newValue;
    private final boolean success;

    public ExtParams(String appId, String key, byte[] value, byte[] newValue, boolean success) {
        this.appId = appId;
        this.key = key;
        this.value = value;
        this.newValue = newValue;
        this.success = success;
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

    public boolean getSuccess() {
        return success;
    }
}
