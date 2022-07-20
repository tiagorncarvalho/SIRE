package sire.coordination;

public class ExtParams {
    private final String key;
    private final byte[] value; //stands for newValue in cas operations
    private final byte[] newValue;

    public ExtParams(String key, byte[] value, byte[] newValue) {
        this.key = key;
        this.value = value;
        this.newValue = newValue;
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
