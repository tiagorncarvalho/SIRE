package sire;

/**
 * @author robin
 */
public enum Operation {
	GENERATE_SIGNING_KEY,
	GET_PUBLIC_KEY,
	SIGN_DATA,
	GET_DATA,
	GET_RANDOM_NUMBER,
	MAP_PUT,
	MAP_DELETE,
	MAP_GET,
	MAP_LIST,
	MAP_CAS;

	public static Operation[] values = values();

	public static Operation getOperation(int ordinal) {
		return values[ordinal];
	}
}
