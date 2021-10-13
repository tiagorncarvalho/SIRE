package sire.proxy;

/**
 * @author robin
 */
public class SireException extends Exception {
	public SireException(String message) {
		super(message);
	}

	public SireException(String message, Throwable throwable) {
		super(message, throwable);
	}
}
