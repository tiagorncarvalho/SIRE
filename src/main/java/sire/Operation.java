package sire;

/**
 * @author robin
 */
public enum Operation {
	GET_RANDOM_NUMBER;

	public static Operation[] values = values();

	public static Operation getOperation(int ordinal) {
		return values[ordinal];
	}
}
