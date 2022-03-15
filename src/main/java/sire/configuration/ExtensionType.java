package sire.configuration;

public enum ExtensionType {
    EXT_JOIN,
    EXT_LEAVE,
    EXT_PING,
    EXT_VIEW,
    EXT_PUT,
    EXT_DEL,
    EXT_GET,
    EXT_CAS,
    EXT_LIST;

    public static ExtensionType[] values = values();

    public static ExtensionType getExtensionType(int ordinal) {
        return values[ordinal];
    }
}
