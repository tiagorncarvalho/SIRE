package sire.client;

import confidential.client.ClientConfidentialityScheme;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.math.ec.ECPoint;
import sire.Operation;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignatureScheme;
import vss.commitment.Commitment;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.facade.Mode;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author robin
 */
public class SireClient {

	public static void main(String[] args) throws SecretSharingException, NoSuchAlgorithmException {
		if (args.length < 1) {
			System.out.println("Usage: sire.client.SireClient <client id>");
			System.exit(-1);
		}
		int clientId = Integer.parseInt(args[0]);
		SchnorrSignatureScheme schnorrSignatureScheme = new SchnorrSignatureScheme();
		ServersResponseHandlerWithoutCombine serversResponseHandler = new ServersResponseHandlerWithoutCombine();
		ConfidentialServiceProxy serviceProxy = new ConfidentialServiceProxy(clientId, serversResponseHandler);
		ClientConfidentialityScheme confidentialityScheme = serviceProxy.getConfidentialityScheme();

		//Asking the verifier to generate the signing key - this operation should be called by a trusted client
		Response signingPublicKeyResponse = serviceProxy.invokeOrdered(new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
		ECPoint signingPublicKey = schnorrSignatureScheme.decodePublicKey(signingPublicKeyResponse.getPainData());
		System.out.println("Signing public key: " + Arrays.toString(signingPublicKey.getEncoded(true)));

		//Reading the verifier's public key
		signingPublicKeyResponse = serviceProxy.invokeOrdered(new byte[]{(byte) Operation.GET_PUBLIC_KEY.ordinal()});
		ECPoint signingPublicKey2 = schnorrSignatureScheme.decodePublicKey(signingPublicKeyResponse.getPainData());
		if (!signingPublicKey.equals(signingPublicKey2)) {
			throw new IllegalStateException("Signing public keys are different");
		}

		//Asking the verifier to sign a message
		byte[] data = "sire".getBytes();
		byte[] signingRequest = new byte[data.length + 1];
		signingRequest[0] = (byte) Operation.SIGN_DATA.ordinal();
		System.arraycopy(data, 0, signingRequest, 1, data.length);
		UncombinedConfidentialResponse signatureResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrdered2(signingRequest);

		PublicPartialSignature partialSignature = null;
		try (ByteArrayInputStream bis = new ByteArrayInputStream(signatureResponse.getPlainData());
			 ObjectInput in = new ObjectInputStream(bis)) {
			partialSignature = PublicPartialSignature.deserialize(schnorrSignatureScheme, in);
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			serviceProxy.close();
			System.exit(-1);
		}
		int f = 1;
		EllipticCurveCommitment signingKeyCommitment = partialSignature.getSigningKeyCommitment();
		EllipticCurveCommitment randomKeyCommitment = partialSignature.getRandomKeyCommitment();
		ECPoint randomPublicKey = partialSignature.getRandomPublicKey();
		VerifiableShare[] verifiableShares = signatureResponse.getVerifiableShares()[0];
		Share[] partialSignatures = new Share[verifiableShares.length];
		for (int i = 0; i < verifiableShares.length; i++) {
			partialSignatures[i] = verifiableShares[i].getShare();
		}

		if (randomKeyCommitment == null)
			throw new IllegalStateException("Random key commitment is null");

		BigInteger sigma = schnorrSignatureScheme.combinePartialSignatures(
				f,
				data,
				signingKeyCommitment,
				randomKeyCommitment,
				randomPublicKey,
				partialSignatures
		);

		boolean isValid = schnorrSignatureScheme.verifySignature(data, signingPublicKey, randomPublicKey, sigma);

		if (isValid) {
			System.out.println("The signature is valid");
		} else {
			System.out.print("The signature is invalid");
		}

		//Asking the verifier to generate a random number
		UncombinedConfidentialResponse randomNumberResponse = (UncombinedConfidentialResponse) serviceProxy.invokeOrdered2(
				new byte[]{(byte) Operation.GET_RANDOM_NUMBER.ordinal()});

		VerifiableShare[] verifiableSharesOfRandomNumber = randomNumberResponse.getVerifiableShares()[0];
		Share[] shares = new Share[verifiableSharesOfRandomNumber.length];
		Map<BigInteger, Commitment> allCommitments = new HashMap<>(verifiableSharesOfRandomNumber.length);
		for (int i = 0; i < verifiableSharesOfRandomNumber.length; i++) {
			VerifiableShare vs = verifiableSharesOfRandomNumber[i];
			shares[i] = vs.getShare();
			allCommitments.put(vs.getShare().getShareholder(), vs.getCommitments());
		}
		Commitment commitment = confidentialityScheme.getCommitmentScheme().combineCommitments(allCommitments);
		OpenPublishedShares openPublishedShares = new OpenPublishedShares(shares, commitment, null);
		BigInteger randomNumber = new BigInteger(confidentialityScheme.combine(openPublishedShares, Mode.SMALL_SECRET));
		System.out.println("Random number: " + randomNumber);
		serviceProxy.close();
	}

}
