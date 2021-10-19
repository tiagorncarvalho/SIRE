package sire.server;

import bftsmart.communication.ServerCommunicationSystem;
import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.core.messages.TOMMessage;
import confidential.ConfidentialMessage;
import confidential.facade.server.ConfidentialSingleExecutable;
import confidential.polynomial.DistributedPolynomialManager;
import confidential.polynomial.RandomPolynomialContext;
import confidential.polynomial.RandomPolynomialListener;
import confidential.server.ConfidentialRecoverable;
import confidential.statemanagement.ConfidentialSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sire.messages.MessageType;
import sire.messages.SireMessage;
import vss.secretsharing.VerifiableShare;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author robin
 */
public class VerifierServer implements ConfidentialSingleExecutable, RandomPolynomialListener {
	private final Logger logger = LoggerFactory.getLogger("sire");
	private static final BigInteger generator = new BigInteger("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16);
	private static final BigInteger primeField = new BigInteger("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16);
	private final ServerCommunicationSystem serverCommunicationSystem;
	private final DistributedPolynomialManager distributedPolynomialManager;
	private final ServiceReplica serviceReplica;

	//used during requests and data map access
	private final Lock lock;
	private final int id;

	//used to store requests asking for a random number
	private Map<Integer, MessageContext> requests;// <polynomial id, MessageContex>
	//used to store random number's shares of clients
	private Map<Integer, VerifiableShare> data;// <client id, random number's share>
	private final Signature signingEngine;
	private final Mac macEngine;
	private final SecretKeyFactory secretKeyFactory;

	//Testing purposes
	private final PrivateKey servicePrivateKey;
	private final PublicKey servicePublicKey;
	private final BigInteger myPrivateSessionKeyPart = new BigInteger("2673e6e0d6f66a15db4fa597b8160f23ab8767ed0e46692e01e04d49bd154426", 16);
	private final BigInteger myPublicSessionKeyPart = generator.modPow(myPrivateSessionKeyPart, primeField);
	private final Device device;

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (args.length < 1) {
			System.out.println("Usage: sire.server.VerifierServer <server id>");
			System.exit(-1);
		}
		new VerifierServer(Integer.parseInt(args[0]));
	}

	public VerifierServer(int id) throws NoSuchAlgorithmException, InvalidKeySpecException {
		this.id = id;
		lock = new ReentrantLock(true);
		requests = new TreeMap<>();
		data = new TreeMap<>();
		ConfidentialRecoverable cr = new ConfidentialRecoverable(id, this);
		serviceReplica = new ServiceReplica(id, cr, cr, null, null, null, null, cr);
		serverCommunicationSystem = serviceReplica.getServerCommunicationSystem();
		distributedPolynomialManager = cr.getDistributedPolynomialManager();
		distributedPolynomialManager.setRandomPolynomialListener(this);

		signingEngine = Signature.getInstance("SHA256withRSA");
		macEngine = Mac.getInstance("HmacSHA256");
		secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

		//hardcoded signing keys for testing - all servers have the same keys
		byte[] encodedPrivateKey = {48, -126, 4, -68, 2, 1, 0, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 4, -126, 4, -90, 48, -126, 4, -94, 2, 1, 0, 2, -126, 1, 1, 0, -97, 84, -15, -30, -56, 33, -24, -97, 49, -1, 104, -90, -79, -110, 26, 97, -27, -40, 73, 86, 46, 37, 108, 75, 108, 106, -37, -125, -67, 115, -102, -7, -80, 3, -3, -8, 51, -66, 106, -3, 95, 93, 124, 54, -113, 71, -44, 113, -25, -105, -45, 8, 114, 22, -21, 112, 118, -108, -96, -35, 71, -5, 24, -50, -78, -120, 69, 86, -57, -36, -21, -50, -64, 12, -58, 46, 50, -59, 29, 102, -23, -27, 81, 75, 2, -104, -125, 59, 103, 43, 97, -81, -94, 68, 72, -61, -119, 103, -127, 89, 28, 122, 70, 28, -89, 45, 92, 22, 66, 115, -18, 70, 41, -125, -89, -103, 18, -99, 26, 74, 46, 116, 44, 1, 90, 103, 7, -37, 52, 49, -52, -110, -47, 33, -125, 100, -100, 1, -95, 82, 65, -7, 53, 122, 10, -98, -79, -45, -75, -128, -33, 62, -46, 8, -89, 14, -48, -41, -13, 83, 34, 106, 47, -25, 10, -55, 77, 75, 110, -14, 64, -118, 29, -20, -96, -58, 77, 19, 36, 117, 53, -110, -53, -40, 13, -67, 102, 85, -126, -19, -119, -128, 81, -96, 8, 102, -36, 0, -105, -81, -19, -111, 47, -61, 33, -56, -86, -60, -43, 118, 21, -16, -110, -84, -8, 101, -32, 111, 106, 62, 32, 48, 110, 11, -99, 66, 81, 57, 5, -34, -123, 11, 39, 119, 103, -13, -49, -124, 50, -66, 13, -29, -114, -128, 38, -59, -87, 92, -120, -58, -30, -9, 126, 19, -12, 15, 2, 3, 1, 0, 1, 2, -126, 1, 0, 4, -31, -99, -119, -29, 77, -66, -92, 25, -20, 58, -93, -14, 85, 34, -116, -108, -36, 72, -34, 23, -92, 59, 16, -21, -83, -104, 0, 115, -44, -49, 117, 65, -94, 58, 121, -40, -61, -6, 121, -16, 81, 1, -30, -105, -97, -13, -17, 63, 4, 33, -119, -104, 26, 1, -88, 34, -3, 22, 76, -111, 51, -58, -66, 47, -6, 111, -106, -4, -44, 33, -90, 25, -81, -67, -77, 97, -44, -50, 34, 100, -48, 113, -124, 34, -106, 5, -9, 57, -70, -19, -23, 4, -5, 8, -110, 13, 4, -101, 94, -35, -71, -30, 16, 103, 15, -112, 24, 18, 124, -73, 39, 117, -20, -17, 60, -18, 78, 116, -91, 34, 91, -103, -7, -121, -42, 126, 58, 121, -102, -126, -40, 70, 113, -47, 31, 70, -38, -34, -23, 114, 44, -3, -126, -97, -10, 12, -12, 84, 55, 83, 47, -110, 50, 108, -38, -101, -57, -32, -15, 79, 115, 32, 24, 2, 105, 16, -106, -45, 14, -39, -84, -12, 70, -79, 62, 11, 21, 127, -124, 12, 84, -82, 111, -120, -100, -8, -6, -79, 30, 51, -97, -98, 104, -104, 13, -15, -46, -112, 97, 35, -4, 126, 124, 87, -56, -28, 62, -38, -9, 50, 123, 61, 88, -65, -27, 48, 10, -12, 69, 107, 73, 101, 114, 29, -109, -4, 18, -47, 96, 37, 59, -69, 30, 2, -99, 127, -78, 75, -49, -93, 88, 79, 121, -30, 12, -26, -62, 16, -58, -92, 24, 56, -5, 13, -119, 2, -127, -127, 0, -51, -19, -45, -66, -118, 113, 13, 122, 29, 10, 23, 114, -9, -92, 66, 27, -109, -37, 121, -1, 57, 89, 2, -116, -58, -74, -66, 126, 4, -75, 8, -22, -22, 10, -104, 88, 99, 113, 89, -5, 16, 84, 7, -109, 118, -42, -101, -75, -47, -126, 64, -121, 9, -28, -14, -63, 40, -19, 34, 64, 7, -115, -10, -31, 41, -7, -110, 30, -102, 34, -37, 13, 58, -80, 86, -79, 32, -22, 25, 21, 61, -108, -116, 75, -98, -9, -53, -128, 114, 121, -112, -115, 54, -115, 100, -42, -119, 113, -120, -90, -128, -69, 24, 55, 109, -109, -68, 93, 95, -115, 19, -51, 62, 86, -120, -93, 70, -68, -116, -78, 29, -20, -46, 56, 80, -14, 108, 61, 2, -127, -127, 0, -58, 18, -91, -45, -96, -111, 38, 113, -64, -8, 20, 11, 120, -68, -5, 95, -50, 108, -128, 97, -75, -11, 101, 113, 83, 118, 35, 100, 29, -77, -105, 12, 22, 115, -1, -23, -18, -81, 67, -82, 39, -108, 14, 103, 10, 44, -38, 105, 1, 37, 51, -103, -43, -103, 37, 85, -118, -36, 12, 84, -35, 39, -16, 33, 45, -105, 26, 72, -69, 99, 78, -8, 72, 111, 66, 98, 3, -33, -61, -123, 79, -36, 90, -27, -85, 54, 6, 56, 73, -24, -11, 66, -76, 99, -57, 24, 124, -2, 23, 100, -21, 56, -60, -105, 23, -107, -6, -116, -121, 102, -91, -125, -12, 90, -49, 68, 87, 25, -127, -5, -52, 77, 35, -16, -54, 111, 42, 59, 2, -127, -128, 93, 106, -64, 29, -75, -21, -25, 51, 56, 45, 53, -55, -1, -79, 82, 19, -12, -107, 33, -40, -72, 9, 58, -16, -27, -52, 76, -54, 26, 20, -114, 1, 19, 62, -49, 49, 121, -101, 24, 56, -98, -123, -96, 18, 51, 92, -45, -78, 61, 98, -101, 39, 39, 67, -25, 35, -35, 15, 5, -12, -119, -8, -54, -64, 6, 44, -93, 46, -94, -71, -95, 41, 117, 48, 61, -125, -120, -20, -23, -120, 11, 49, 114, 27, 115, -9, -15, 39, 73, -58, -1, -34, 47, -101, 32, -35, 121, -24, 57, 23, 95, 90, -128, 119, -44, -117, -86, 109, -87, 68, -12, 112, -83, 16, -48, 87, 81, 101, -125, 101, -31, -47, 102, -28, 9, 68, -113, -7, 2, -127, -128, 44, 111, 22, -128, 73, 47, 6, -66, -46, 25, 84, -11, -43, -38, 31, 82, 56, -50, -94, 102, 73, 25, -119, -18, 72, 88, -30, 75, -99, 86, 34, 118, 117, -69, 4, 24, 8, -111, -116, -49, 78, -43, -87, -3, 119, -116, -28, 90, 86, 5, 112, 115, -4, 52, -28, -23, 49, -61, 119, -120, -70, 44, 49, 116, 95, -13, -37, -45, -95, 38, 0, 27, 54, -76, -82, -31, -86, 24, -46, -107, -33, 122, -127, 113, -80, 92, -24, 60, 76, 104, 84, 76, -24, -122, -47, -83, 46, -83, 25, -74, 108, 6, 74, 35, -45, 8, -76, 50, 62, 85, -54, -97, -75, 123, -127, -81, -59, 18, 85, -44, -108, -38, 97, 75, -83, 62, 14, -19, 2, -127, -128, 96, -103, -1, 47, 3, -40, -11, -72, -118, 41, 108, -120, -2, 107, 6, -101, 119, 81, 122, 62, 104, -32, 97, 53, 101, -65, -40, 66, 50, -33, -75, 30, -71, 38, -85, -117, -121, 114, -71, 92, -38, -97, -101, 116, -111, -59, -77, -80, -124, 54, 19, -30, 95, -60, 84, 83, 19, 38, -95, 124, 21, -79, -111, 105, -78, 109, 99, -44, -8, -18, 69, 12, 127, 16, -33, -98, 94, -60, 71, 126, -104, -96, -20, -105, -23, -65, 10, 82, 17, 116, 119, -60, 87, 5, -15, -101, -75, -36, 51, 7, -104, -118, 9, -95, -90, 3, 31, 32, -3, -34, 4, 108, 28, -126, -54, -10, 61, 13, -121, 74, 119, 122, -30, -42, -123, -59, 43, 16};
		byte[] encodedPublicKey = {48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -97, 84, -15, -30, -56, 33, -24, -97, 49, -1, 104, -90, -79, -110, 26, 97, -27, -40, 73, 86, 46, 37, 108, 75, 108, 106, -37, -125, -67, 115, -102, -7, -80, 3, -3, -8, 51, -66, 106, -3, 95, 93, 124, 54, -113, 71, -44, 113, -25, -105, -45, 8, 114, 22, -21, 112, 118, -108, -96, -35, 71, -5, 24, -50, -78, -120, 69, 86, -57, -36, -21, -50, -64, 12, -58, 46, 50, -59, 29, 102, -23, -27, 81, 75, 2, -104, -125, 59, 103, 43, 97, -81, -94, 68, 72, -61, -119, 103, -127, 89, 28, 122, 70, 28, -89, 45, 92, 22, 66, 115, -18, 70, 41, -125, -89, -103, 18, -99, 26, 74, 46, 116, 44, 1, 90, 103, 7, -37, 52, 49, -52, -110, -47, 33, -125, 100, -100, 1, -95, 82, 65, -7, 53, 122, 10, -98, -79, -45, -75, -128, -33, 62, -46, 8, -89, 14, -48, -41, -13, 83, 34, 106, 47, -25, 10, -55, 77, 75, 110, -14, 64, -118, 29, -20, -96, -58, 77, 19, 36, 117, 53, -110, -53, -40, 13, -67, 102, 85, -126, -19, -119, -128, 81, -96, 8, 102, -36, 0, -105, -81, -19, -111, 47, -61, 33, -56, -86, -60, -43, 118, 21, -16, -110, -84, -8, 101, -32, 111, 106, 62, 32, 48, 110, 11, -99, 66, 81, 57, 5, -34, -123, 11, 39, 119, 103, -13, -49, -124, 50, -66, 13, -29, -114, -128, 38, -59, -87, 92, -120, -58, -30, -9, 126, 19, -12, 15, 2, 3, 1, 0, 1};

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		servicePublicKey = keyFactory.generatePublic(publicKeySpec);
		EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(encodedPrivateKey);
		servicePrivateKey = keyFactory.generatePrivate(privateKeySpec);

		byte[] devicePublicKeyBytes = {48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -41, -26, 10, -62, -2, -97, 123, 113, -21, 88, -127, 93, 95, 96, 18, 44, 47, -97, -45, -125, 32, -85, -11, -123, 63, -70, -29, -95, 16, 21, 102, 60, 106, -105, -115, -90, 29, 6, 119, -54, -47, -70, 13, -94, -52, -86, 59, 61, 43, 1, 87, 69, -99, -30, -59, 102, -58, -97, 83, 22, -16, 84, 95, -114, -100, 19, 77, -77, -68, 39, 91, 95, -117, 44, 89, 105, 22, 107, -30, -77, 38, 108, 97, -34, 21, -79, 28, -12, 39, 12, 52, -101, 17, -36, -38, -60, -98, 17, 46, 79, 80, -53, -99, -123, 29, -79, -45, 119, 23, 14, -81, -35, -19, -107, 64, 89, 14, 102, 12, 113, 105, 45, 50, -100, 80, -33, -10, 93, -113, 22, 17, -75, -17, -63, 32, 36, 45, -55, 70, 33, 23, -61, 62, 49, -75, 45, 99, -83, 37, 41, -109, -32, -79, 48, 65, -76, -40, 62, -47, 25, 87, 55, -7, -37, -61, -18, -64, 120, 113, -44, 119, 75, 104, 40, -66, -93, -103, -1, -63, -3, 123, -72, 82, -15, 64, -109, 40, 64, -120, -46, 24, -116, 39, 33, 109, -56, -15, -79, -109, -67, -128, -16, 15, -24, 96, 98, -115, -93, 60, 7, -118, 76, -1, -21, 46, 37, 24, 62, -51, -9, 58, 82, -5, 83, -123, -19, 39, -84, -69, 67, 99, 69, -86, -92, 84, -59, -95, -101, 2, -81, 96, -19, -35, 53, 48, -121, 94, -27, 15, -67, 43, -46, -15, -32, 94, 105, 2, 3, 1, 0, 1};
		EncodedKeySpec devicePublicKeySpec = new X509EncodedKeySpec(devicePublicKeyBytes);
		PublicKey devicePublicKey = keyFactory.generatePublic(devicePublicKeySpec);
		device = new Device(devicePublicKey);
	}

	@Override
	public ConfidentialMessage appExecuteOrdered(byte[] bytes, VerifiableShare[] verifiableShares,
												 MessageContext messageContext) {
		/*
		try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
			 ObjectInputStream in = new ObjectInputStream(bis)) {
			MessageType messageType = MessageType.getMessageType(in.read());
			logger.debug("Received a {} request from {} in cid {}", messageType, messageContext.getSender(),
					messageContext.getConsensusId());
			switch (messageType) {
				case MESSAGE_0 -> {
					Message0 message0 = new Message0();
					message0.readExternal(in);
					BigInteger sharedSecretKeyNumber = new BigInteger(message0.getEncodedAttesterSessionPublicKey())
							.modPow(myPrivateSessionKeyPart, primeField);
					SecretKey sharedSecretKey = createSecretKey(sharedSecretKeyNumber.toString().toCharArray());
					Application application = new Application(message0.getAttesterId());
					application.setSessionKey(sharedSecretKey);
					device.addApplication(application);

					//creating response
					byte[] signatureOfSessionKeys = createSignature(servicePrivateKey,
							myPublicSessionKeyPart.toByteArray(), message0.getEncodedAttesterSessionPublicKey());
					byte[] mac = createMac(sharedSecretKey, myPublicSessionKeyPart.toByteArray(),
							servicePublicKey.getEncoded(), signatureOfSessionKeys);
					Message1 response = new Message1(myPublicSessionKeyPart.toByteArray(),
							servicePublicKey.getEncoded(), signatureOfSessionKeys, mac);
					return new ConfidentialMessage(serializeMessage(MessageType.MESSAGE_1, response));
				}
			}
		} catch (IOException | ClassNotFoundException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
			logger.error("Failed to process message from {} in cid {}", messageContext.getSender(),
					messageContext.getConsensusId());
		}

		/*Operation op = Operation.getOperation(bytes[0]);
		logger.debug("Received a {} request from {} in cid {}", op, messageContext.getSender(),
				messageContext.getConsensusId());
		switch (op) {
			case GET_RANDOM_NUMBER -> {
				lock.lock();
				VerifiableShare	share = data.get(messageContext.getSender());
				if (share == null)
					generateRandomNumberFor(messageContext);
				else {
					logger.debug("Sending existing random number share to {}", messageContext.getSender());
					sendRandomNumberShareTo(messageContext, share);
				}
				lock.unlock();
			}
		}*/
		return null;
	}

	private static byte[] serializeMessage(MessageType type, SireMessage message) {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutputStream out = new ObjectOutputStream(bos)) {
			out.write(type.ordinal());
			message.writeExternal(out);
			out.flush();
			bos.flush();
			return bos.toByteArray();
		} catch (IOException e) {
			System.err.println("Failed to serialize a message");
			e.printStackTrace();
		}
		return null;
	}

	private byte[] createMac(SecretKey secretKey, byte[]... contents) throws InvalidKeyException {
		macEngine.init(secretKey);
		for (byte[] content : contents) {
			macEngine.update(content);
		}
		return macEngine.doFinal();
	}

	private SecretKey createSecretKey(char[] password) throws InvalidKeySpecException {
		KeySpec spec = new PBEKeySpec(password);
		return new SecretKeySpec(secretKeyFactory.generateSecret(spec).getEncoded(), "AES");
	}

	private byte[] createSignature(PrivateKey signingKey, byte[]... contents) throws InvalidKeyException, SignatureException {
		signingEngine.initSign(signingKey);
		for (byte[] content : contents) {
			signingEngine.update(content);
		}
		return signingEngine.sign();
	}

	/**
	 * Method used to generate a random number
	 * @param messageContext Message context of the client requesting the generation of a random number
	 */
	private void generateRandomNumberFor(MessageContext messageContext) {
		int id = distributedPolynomialManager.createRandomPolynomial(serviceReplica.getReplicaContext().getCurrentView().getF(),
				serviceReplica.getReplicaContext().getCurrentView().getProcesses());
		requests.put(id, messageContext);
	}

	/**
	 * Method used to asynchronously send the random number share
	 * @param receiverContext Information about the requesting client
	 * @param share Random number share
	 */
	public void sendRandomNumberShareTo(MessageContext receiverContext, VerifiableShare share) {
		ConfidentialMessage response = new ConfidentialMessage(null, share);//maybe send encrypted if needed (e.g., when tls encryption is off)
		TOMMessage tomMessage = new TOMMessage(
				id,
				receiverContext.getSession(),
				receiverContext.getSequence(),
				receiverContext.getOperationId(),
				response.serialize(),
				serviceReplica.getReplicaContext().getSVController().getCurrentViewId(),
				receiverContext.getType()
		);
		serverCommunicationSystem.send(new int[]{receiverContext.getSender()}, tomMessage);
	}

	/**
	 * Method called by the polynomial generation manager when the requested random number is generated
	 * @param context Random number share and its context
	 */
	@Override
	public void onRandomPolynomialsCreation(RandomPolynomialContext context) {
		lock.lock();
		double delta = context.getTime() / 1_000_000.0;
//		logger.debug("Received random number polynomial with id {} in {} ms", context.getId(), delta);
		MessageContext messageContext = requests.get(context.getId());
		data.put(messageContext.getSender(), context.getPoint());
//		logger.debug("Sending random number share to {}", messageContext.getSender());
		sendRandomNumberShareTo(messageContext, context.getPoint());
		lock.unlock();
	}

	@Override
	public ConfidentialMessage appExecuteUnordered(byte[] bytes, VerifiableShare[] verifiableShares, MessageContext messageContext) {
		return null;
	}

	@Override
	public ConfidentialSnapshot getConfidentialSnapshot() {
		try (ByteArrayOutputStream bout = new ByteArrayOutputStream();
			 ObjectOutput out = new ObjectOutputStream(bout)) {
			out.writeInt(requests.size());
			for (Map.Entry<Integer, MessageContext> entry : requests.entrySet()) {
				out.writeInt(entry.getKey());
				out.writeObject(entry.getValue());
			}
			out.writeInt(data.size());
			VerifiableShare[] shares = new VerifiableShare[data.size()];
			int index = 0;
			for (Map.Entry<Integer, VerifiableShare> entry : data.entrySet()) {
				out.writeInt(entry.getKey());
				entry.getValue().writeExternal(out);
				shares[index++] = entry.getValue();
			}
			out.flush();
			bout.flush();
			return new ConfidentialSnapshot(bout.toByteArray(), shares);
		} catch (IOException e) {
//			logger.error("Error while taking snapshot", e);
		}
		return null;
	}

	@Override
	public void installConfidentialSnapshot(ConfidentialSnapshot confidentialSnapshot) {
		try (ByteArrayInputStream bin = new ByteArrayInputStream(confidentialSnapshot.getPlainData());
			 ObjectInput in = new ObjectInputStream(bin)) {
			int size = in.readInt();
			requests = new TreeMap<>();
			while (size-- > 0) {
				int key = in.readInt();
				MessageContext value = (MessageContext) in.readObject();
				requests.put(key, value);
			}
			size = in.readInt();
			data = new TreeMap<>();
			VerifiableShare[] shares = confidentialSnapshot.getShares();
			for (int i = 0; i < size; i++) {
				int key = in.readInt();
				VerifiableShare value = shares[i];
				value.readExternal(in);
				data.put(key, value);
			}
		} catch (IOException | ClassCastException | ClassNotFoundException e) {
//			logger.error("Error while installing snapshot", e);
		}
	}
}
