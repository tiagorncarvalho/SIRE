package sire.coordination;

public class ExtParams {
    private String key;
    private final byte[] value; //stands for oldValue in cas operations
    private final byte[] newValue;

    public ExtParams(String key, byte[] value, byte[] newValue) {
        this.key = key;
        this.value = value;
        this.newValue = newValue;
    }

    public void setKey(String key) {
        this.key = key;
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
