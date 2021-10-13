package sire.playground;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import sire.proxy.SireException;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * @author robin
 */
public class SymmetricEncryption {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
		BigInteger sharedSecret = new BigInteger("97fccab1690edea6dac39ca0f0a698153537cacdeff214abb5232728f9d79e85", 16);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

		String salt = "123";
		byte[] data = "Hello World".getBytes();
		System.out.println("Data: " + new String(data));

		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(sharedSecret.toString().toCharArray(), salt.getBytes(), 65536, 128);
		SecretKey key = new SecretKeySpec(secretKeyFactory.generateSecret(spec).getEncoded(), "AES");

		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedData = cipher.doFinal(data);

		byte[] iv = cipher.getIV();
		GCMParameterSpec params = new GCMParameterSpec(128, iv);
		cipher.init(Cipher.DECRYPT_MODE, key, params);
		byte[] decryptedData = cipher.doFinal(encryptedData);

		if (!Arrays.equals(data, decryptedData))
			throw new IllegalStateException("Decrypted data is different");
		System.out.println("Decrypted data: " + new String(decryptedData));
	}

}
