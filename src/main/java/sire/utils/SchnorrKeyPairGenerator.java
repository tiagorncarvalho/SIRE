package sire.utils;

import org.bouncycastle.math.ec.ECPoint;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.commitment.ellipticCurve.EllipticCurveCommitmentScheme;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SchnorrKeyPairGenerator {
	public static void main(String[] args) {
		int nKeys = 100;
		int t = 3;
		int n = 3 * t + 1;

		BigInteger[] shareholders = new BigInteger[n];
		for (int i = 0; i < n; i++) {
			shareholders[i] = BigInteger.valueOf(i + 1);
		}

		BigInteger prime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
		BigInteger order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
		BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
		BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
		byte[] compressedGenerator = new BigInteger("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).toByteArray();
		EllipticCurveCommitmentScheme commitmentScheme = new EllipticCurveCommitmentScheme(prime, order, a, b, compressedGenerator);

		SecureRandom rndGenerator = new SecureRandom();

		ECPoint[] publicKeys = new ECPoint[nKeys];
		Share[][] privateKeyShares = new Share[n][nKeys];
		EllipticCurveCommitment[] commitments = new EllipticCurveCommitment[nKeys];

		for (int i = 0; i < nKeys; i++) {
			BigInteger privateKey = new BigInteger(order.bitLength(), rndGenerator).mod(order);
			Polynomial polynomial = new Polynomial(order, t, privateKey, rndGenerator);

			EllipticCurveCommitment commitment = (EllipticCurveCommitment) commitmentScheme.generateCommitments(polynomial);
			publicKeys[i] = commitment.getCommitment()[commitment.getCommitment().length - 1];
			commitments[i] = commitment;
			for (int j = 0; j < shareholders.length; j++) {
				BigInteger shareholder = shareholders[j];
				BigInteger shareNumber = polynomial.evaluateAt(shareholder);
				privateKeyShares[j][i] = new Share(shareholder, shareNumber);
			}
		}

		String dstDirName = "D:\\IntelliJ\\SIRE\\config\\schnorr";
		String fileSeparator = File.separator;
		String publicKeysFileName = dstDirName + fileSeparator + t + "_publicKeys.txt";
		String commitmentsFileName = dstDirName + fileSeparator + t + "_commitments.txt";

		try (FileOutputStream fos = new FileOutputStream(publicKeysFileName);
			 ObjectOutput out = new ObjectOutputStream(fos)) {
			out.writeInt(nKeys);
			for (ECPoint publicKey : publicKeys) {
				byte[] encodedKey = commitmentScheme.encodePoint(publicKey);
				out.writeInt(encodedKey.length);
				out.write(encodedKey);
			}
			out.flush();
			fos.flush();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		try (FileOutputStream fos = new FileOutputStream(commitmentsFileName);
			 ObjectOutput out = new ObjectOutputStream(fos)) {
			out.writeInt(nKeys);
			for (EllipticCurveCommitment commitment : commitments) {
				out.writeObject(commitment);
			}
			out.flush();
			fos.flush();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		for (int i = 0; i < shareholders.length; i++) {
			String shareFileName = dstDirName + fileSeparator + t + "_" + i + "_commitments.txt";
			Share[] shares = privateKeyShares[i];
			try (FileOutputStream fos = new FileOutputStream(shareFileName);
				 ObjectOutput out = new ObjectOutputStream(fos)) {
				out.writeInt(nKeys);
				for (Share share : shares) {
					out.writeObject(share);
				}
				out.flush();
				fos.flush();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}
}
