package sire.dummy;

import java.security.*;
import java.util.Arrays;

/**
 * @author robin
 */
public class KeyGenerator {
	public static void main(String[] args) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();

		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();

		System.out.println(Arrays.toString(privateKey.getEncoded()));

		System.out.println();

		System.out.println(Arrays.toString(publicKey.getEncoded()));
	}
}
