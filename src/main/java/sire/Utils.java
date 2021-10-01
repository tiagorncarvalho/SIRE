package sire;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class Utils {
	public static void writeByteArray(ObjectOutput out, byte[] arr) throws IOException {
		out.writeInt(arr == null ? -1 : arr.length);
		if (arr != null)
			out.write(arr);
	}

	public static byte[] readByteArray(ObjectInput in) throws IOException {
		int len = in.readInt();
		if (len > -1) {
			byte[] result = new byte[len];
			in.readFully(result);
			return result;
		}
		return null;
	}
}
