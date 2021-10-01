package sire.messages;

/**
 * @author robin
 */
public enum MessageType {
	MESSAGE_0,
	MESSAGE_1,
	MESSAGE_2;

	public static MessageType[] values = values();

	public static MessageType getMessageType(int ordinal) {
		return values[ordinal];
	}
}
