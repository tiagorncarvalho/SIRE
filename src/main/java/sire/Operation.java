package sire;

/**
 * @author robin
 */
public enum Operation {
	GENERATE_SIGNING_KEY,
	GET_PUBLIC_KEY,
	SIGN_DATA,
	GET_RANDOM_NUMBER;

	public static Operation[] values = values();

	public static Operation getOperation(int ordinal) {
		return values[ordinal];
	}
}
