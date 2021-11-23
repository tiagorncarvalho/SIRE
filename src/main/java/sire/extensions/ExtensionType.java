package sire.extensions;

public enum ExtensionType {
    JOIN,
    LEAVE,
    PING,
    VIEW;

    public static ExtensionType[] values = values();

    public static ExtensionType getExtensionType(int ordinal) {
        return values[ordinal];
    }
}
