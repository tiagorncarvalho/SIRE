package sire.coordination;

public enum ExtensionType {
    EXT_JOIN,
    EXT_LEAVE,
    EXT_PING,
    EXT_VIEW,
    EXT_PUT,
    EXT_DEL,
    EXT_GET,
    EXT_CAS,
    EXT_LIST,
    EXT_ATTEST;

    public static final ExtensionType[] values = values();

    public static ExtensionType getExtensionType(int ordinal) {
        return values[ordinal];
    }
}
