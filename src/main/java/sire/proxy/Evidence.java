package sire.proxy;

/**
 * @author robin
 */
public class Evidence {
	private final byte[] anchor;

	public Evidence(byte[] anchor) {
		this.anchor = anchor;
	}

	public byte[] getAnchor() {
		return anchor;
	}
}
