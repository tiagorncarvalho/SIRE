/*
 * Copyright 2023 Tiago Carvalho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sire.proxy;

import com.google.protobuf.ByteString;
import confidential.client.Response;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import sire.messages.Messages.*;
import sire.serverProxyUtils.*;

import static sire.messages.ProtoUtils.*;

import sire.schnorr.SchnorrSignatureScheme;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @author Tiago
 */

public class SocketProxyMock implements Runnable {
	private static final int AES_KEY_LENGTH = 128;
	//private final ConfidentialServiceProxy serviceProxy;
	//private final ECPoint verifierPublicKey;
	private final SchnorrSignatureScheme signatureScheme;
	private final int proxyId;
	//private final Object proxyLock;

	public SocketProxyMock(int proxyId) throws SireException{
		System.out.println("Proxy start!");
		this.proxyId = proxyId;
		/*try {
			ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
			//serviceProxy = new ConfidentialServiceProxy(proxyId, responseHandler);
			proxyLock = new Object();
		} catch (SecretSharingException e) {
			throw new SireException("Failed to contact the distributed verifier", e);
		}*/
		System.out.println("Connection established!");
		try {
			BlockCipher aes = new AESEngine();

			signatureScheme = new SchnorrSignatureScheme();
		} catch (NoSuchAlgorithmException e) {
			throw new SireException("Failed to initialize cryptographic tools", e);
		}
		Response response;
		/*try {
			ProxyMessage msg = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.ATTEST_GET_PUBLIC_KEY)
					.build();
			byte[] b = msg.toByteArray();
			//response = serviceProxy.invokeOrdered(b);//new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
		} catch (SecretSharingException e) {
			throw new SireException("Failed to obtain verifier's public key", e);
		}
		verifierPublicKey = signatureScheme.decodePublicKey(response.getPainData());*/

	}

	@Override
	public void run() {
		try {
			ServerSocket ss = new ServerSocket(2500 + this.proxyId);
			Socket s;
			while(true) {
				s = ss.accept();
				System.out.println("New client!");
				new SireProxyThread(s).start();
				System.out.println("Connection accepted");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private class SireProxyThread extends Thread {

		private final Socket s;

		public SireProxyThread(Socket s) {
			this.s = s;
			System.out.println("Proxy Thread started!");
		}
		@Override
		public void run() {
			try {
				OutputStream os = s.getOutputStream();
				DataOutputStream dos = new DataOutputStream(os);
				InputStream is = s.getInputStream();

				while (!s.isClosed()) {
					int size = ByteBuffer.wrap(is.readNBytes(4)).getInt();
					byte[] bytes = is.readNBytes(size);
					ProxyMessage msg = readMessage(bytes);
					//= ProxyMessage.parseFrom(bytes);

					if (msg.getOperation() == ProxyMessage.Operation.ATTEST_GET_PUBLIC_KEY) {
						//oos.writeObject(SchnorrSignatureScheme.encodePublicKey(verifierPublicKey));
						System.out.println("Wrong operation!");
					} else {
						ProxyResponse result = runProxyMessageMock(msg);
						if (result != null) {
							byte[] bs = writeMessage(result);//result.toByteArray();
							dos.writeInt(bs.length);
							dos.write(bs);
						}
					}
					dos.flush();
				}
			} catch (IOException | java.nio.BufferUnderflowException ignored) {}
		}

		private byte[] writeMessage(ProxyResponse response) {
			if(response.getType() == ProxyResponse.ResponseType.PREJOIN)
				return writeMessage1(response);
			else if(response.getType() == ProxyResponse.ResponseType.PREJOIN_MQTT || response.getType() == ProxyResponse
					.ResponseType.JOIN_MQTT)
				return writeMessage1n3MQTT(response);
			else if(response.getType() == ProxyResponse.ResponseType.JOIN)
				return writeMessage3(response);
			else
				return new byte[0];
		}

		private byte[] writeMessage1n3MQTT(ProxyResponse response) {
			try {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] timestamp = byteStringToByteArray(baos, response.getTimestamp());
				byte[] timestampLen = BigInteger.valueOf(timestamp.length).toByteArray();
				baos.write(timestampLen);
				baos.write(timestamp);
				return baos.toByteArray();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return new byte[0];
		}

		private byte[] writeMessage3(ProxyResponse response) {
			try {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] pubKey = byteStringToByteArray(baos, response.getPubKey());
				byte[] pubKeyLen = BigInteger.valueOf(pubKey.length).toByteArray();
				byte[] timestamp = byteStringToByteArray(baos, response.getTimestamp());
				byte[] timestampLen = BigInteger.valueOf(timestamp.length).toByteArray();
				byte[] hash = byteStringToByteArray(baos, response.getHash());
				byte[] hashLen = BigInteger.valueOf(hash.length).toByteArray();
				baos.write(pubKeyLen);
				baos.write(pubKey);
				baos.write(timestampLen);
				baos.write(timestamp);
				baos.write(hashLen);
				baos.write(hash);
				return baos.toByteArray();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return new byte[0];
		}

		private byte[] writeMessage1(ProxyResponse response) {
			try {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] pubKey = byteStringToByteArray(baos, response.getPubKey());
				byte[] pubKeyLen = BigInteger.valueOf(pubKey.length).toByteArray();
				byte[] timestamp = byteStringToByteArray(baos, response.getTimestamp());
				byte[] timestampLen = BigInteger.valueOf(timestamp.length).toByteArray();
				baos.write(pubKeyLen);
				baos.write(pubKey);
				baos.write(timestampLen);
				baos.write(timestamp);
				return baos.toByteArray();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return new byte[0];
		}

		private ProxyMessage readMessage(byte[] bytes) throws IOException {
			int op = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 4)).getInt();
			if(op == 1)
				return readMessage0(Arrays.copyOfRange(bytes, 4, bytes.length));
			else if(op == 2)
				return readMessage0MQTT(Arrays.copyOfRange(bytes, 4, bytes.length));
			else if(op == 8)
				return readMessage2(Arrays.copyOfRange(bytes, 4, bytes.length));
			else if(op == 9)
				return readMessage2MQTT(Arrays.copyOfRange(bytes, 4, bytes.length));
			else
				throw new IOException();
		}

		private ProxyMessage readMessage0MQTT(byte[] bytes) {
			int idLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 4)).getInt();
			String id = new String(Arrays.copyOfRange(bytes, 4, 4 + idLen));
			int appIdLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 4 + idLen, 8 + idLen)).getInt();
			String appId = new String(Arrays.copyOfRange(bytes, 8 + idLen, 8 + idLen + appIdLen));
			return ProxyMessage.newBuilder()
					.setDeviceId(id)
					.setAppId(appId)
					.setOperation(ProxyMessage.Operation.ATTEST_TIMESTAMP_MQTT)
					.build();
		}

		private ProxyMessage readMessage2MQTT(byte[] bytes) {
			int idLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 4)).getInt();
			String id = new String(Arrays.copyOfRange(bytes, 4, 4 + idLen));
			int appIdLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 4 + idLen, 8 + idLen)).getInt();
			String appId = new String(Arrays.copyOfRange(bytes, 8 + idLen, 8 + idLen + appIdLen));
			int securityVersion = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8 + idLen + appIdLen,
					12 + idLen + appIdLen)).getInt();
			int productId = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 12 + idLen + appIdLen,
					16 + idLen + appIdLen)).getInt();
			int claimLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 16 + idLen + appIdLen,
					20 + idLen + appIdLen)).getInt();
			byte[] claim = Arrays.copyOfRange(bytes, 20 + idLen + appIdLen, 20 + idLen + appIdLen
					+ claimLen);
			int nonceLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 20 + idLen + appIdLen + claimLen,
					24 + idLen + appIdLen + claimLen)).getInt();
			String nonce = new String(Arrays.copyOfRange(bytes, 24 + idLen + appIdLen + claimLen,
					24 + idLen + appIdLen + claimLen + nonceLen));
			int mrEnclaveLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 24 + idLen + appIdLen + claimLen + nonceLen,
					28 + idLen + appIdLen + claimLen + nonceLen)).getInt();
			byte[] mrEnclave = Arrays.copyOfRange(bytes, 28 + idLen + appIdLen + claimLen + nonceLen,
					28 + idLen + appIdLen + claimLen + nonceLen + mrEnclaveLen);
			int mrSignerLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 28 + idLen + appIdLen + claimLen
							+ nonceLen + mrEnclaveLen, 32 + idLen + appIdLen + claimLen + nonceLen + mrEnclaveLen)).getInt();
			byte[] mrSigner = Arrays.copyOfRange(bytes, 32 + idLen + appIdLen + claimLen + nonceLen + mrEnclaveLen,
					32 + idLen + appIdLen + claimLen + nonceLen + mrEnclaveLen + mrSignerLen);
			int tsLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 32 + idLen + appIdLen + claimLen + nonceLen +
					mrEnclaveLen + mrSignerLen, 36 + idLen + appIdLen + claimLen + nonceLen + mrEnclaveLen + mrSignerLen)).getInt();
			byte[] ts = Arrays.copyOfRange(bytes, 36 + idLen + appIdLen + claimLen + nonceLen + mrEnclaveLen + mrSignerLen,
					36 + idLen + appIdLen + claimLen + nonceLen + mrEnclaveLen + mrSignerLen + tsLen);


			ProtoMQTTEvidence mqttEvidence = ProtoMQTTEvidence.newBuilder()
					.setSecurityVersion(securityVersion)
					.setProductId(productId)
					.setClaim(ByteString.copyFrom(claim))
					.setNonce(nonce)
					.setMrEnclave(ByteString.copyFrom(mrEnclave))
					.setMrSigner(ByteString.copyFrom(mrSigner))
					.build();
			return ProxyMessage.newBuilder()
					.setDeviceId(id)
					.setAppId(appId)
					.setMqttEvidence(mqttEvidence)
					.setTimestamp(ByteString.copyFrom(ts))
					.setOperation(ProxyMessage.Operation.MEMBERSHIP_JOIN_MQTT)
					.build();
		}

		private ProxyMessage readMessage2(byte[] bytes) {
			int idLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 4)).getInt();
			String id = new String(Arrays.copyOfRange(bytes, 4, 4 + idLen));
			int appIdLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 4 + idLen, 8 + idLen)).getInt();
			String appId = new String(Arrays.copyOfRange(bytes, 8 + idLen, 8 + idLen + appIdLen));
			int pubKeyLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8 + idLen + appIdLen, 12 + idLen
					+ appIdLen)).getInt();
			byte[] pubKey = Arrays.copyOfRange(bytes, 12 + idLen + appIdLen, 12 + idLen + appIdLen + pubKeyLen);
			int versionLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 12 + idLen + appIdLen + pubKeyLen,
					16 + idLen + appIdLen + pubKeyLen)).getInt();
			String version = new String(Arrays.copyOfRange(bytes, 16 + idLen + appIdLen + pubKeyLen,
					16 + idLen + appIdLen + pubKeyLen + versionLen));
			int claimLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 16 + idLen + appIdLen + pubKeyLen + versionLen,
					20 + idLen + appIdLen + pubKeyLen + versionLen)).getInt();
			byte[] claim = Arrays.copyOfRange(bytes, 20 + idLen + appIdLen + pubKeyLen + versionLen,
					20 + idLen + appIdLen + pubKeyLen + versionLen + claimLen);
			int timestampLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 20 + idLen + appIdLen + pubKeyLen + versionLen + claimLen,
					24 + idLen + appIdLen + pubKeyLen + versionLen + claimLen)).getInt();
			byte[] timestamp = Arrays.copyOfRange(bytes, 24 + idLen + appIdLen + pubKeyLen + versionLen + claimLen,
					24 + idLen + appIdLen + pubKeyLen + versionLen + claimLen + timestampLen);
			int signatureLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 24 + idLen + appIdLen + pubKeyLen + versionLen + claimLen + timestampLen,
					28 + idLen + appIdLen + pubKeyLen + versionLen + claimLen + timestampLen)).getInt();
			byte[] signature = Arrays.copyOfRange(bytes, 28 + idLen + appIdLen + pubKeyLen + versionLen + claimLen + timestampLen,
					28 + idLen + appIdLen + pubKeyLen + versionLen + claimLen + timestampLen + signatureLen);

			ProtoEvidence protoEvidence = ProtoEvidence.newBuilder()
					.setVersion(version)
					.setClaim(ByteString.copyFrom(claim))
					.setServicePubKey(ByteString.copyFrom(pubKey))
					.build();
			ProtoSchnorr protoSchnorr = ProtoSchnorr.newBuilder()
					.setSigma(ByteString.copyFrom(signature))
					.build();

			return ProxyMessage.newBuilder()
					.setDeviceId(id)
					.setAppId(appId)
					.setPubKey(ByteString.copyFrom(pubKey))
					.setOperation(ProxyMessage.Operation.MEMBERSHIP_JOIN)
					.setEvidence(protoEvidence)
					.setSignature(protoSchnorr)
					.setTimestamp(ByteString.copyFrom(timestamp))
					.build();
		}

		private ProxyMessage readMessage0(byte[] bytes) {
			int idLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 4)).getInt();
			String id = new String(Arrays.copyOfRange(bytes, 4, 4 + idLen));
			int appIdLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 4 + idLen, 8 + idLen)).getInt();
			String appId = new String(Arrays.copyOfRange(bytes, 8 + idLen, 8 + idLen + appIdLen));
			int pubKeyLen = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8 + idLen + appIdLen, 12 + idLen
					+ appIdLen)).getInt();
			byte[] pubKey = Arrays.copyOfRange(bytes, 12 + idLen + appIdLen, 12 + idLen + appIdLen + pubKeyLen);
			return ProxyMessage.newBuilder()
					.setDeviceId(id)
					.setAppId(appId)
					.setPubKey(ByteString.copyFrom(pubKey))
					.setOperation(ProxyMessage.Operation.ATTEST_TIMESTAMP)
					.build();
		}

		private ProxyResponse runProxyMessageMock(ProxyMessage msg) throws IOException {
			if(msg.getOperation() == ProxyMessage.Operation.ATTEST_TIMESTAMP)
				return timestampAttMock(msg);
				//return timestampAtt(serviceProxy.invokeOrdered2(msg.toByteArray()));
			else if(msg.getOperation() == ProxyMessage.Operation.ATTEST_TIMESTAMP_MQTT)
				return timestampAttMQTTMock(msg);
			else if(msg.getOperation() == ProxyMessage.Operation.MEMBERSHIP_JOIN)
				return joinMock(msg);
			else if(msg.getOperation() == ProxyMessage.Operation.MEMBERSHIP_JOIN_MQTT)
				return joinMQTTMock(msg);
			else
				return null;
		}

		private ProxyResponse joinMQTTMock(ProxyMessage msg) throws IOException {
			boolean isVerified = verifyMQTTEvidence(msg.getMqttEvidence());
			java.sql.Timestamp ts = new java.sql.Timestamp(System.currentTimeMillis());
			System.out.println("MQTT with id " + msg.getDeviceId() + " attested at " + ts);
			if(isVerified)
				return ProxyResponse.newBuilder()
						.setTimestamp(ByteString.copyFrom(serialize(ts)))
						.setType(ProxyResponse.ResponseType.JOIN_MQTT)
						.build();
			else
				return ProxyResponse.newBuilder().build();
		}

		private boolean verifyMQTTEvidence(ProtoMQTTEvidence evidence) throws IOException {
			byte[] hashClaim = computeHash("measure1".getBytes());
			byte[] computedClaim = computeHash(hashClaim, evidence.getNonce().getBytes());
			byte[] sentCompClaim = byteStringToByteArray(new ByteArrayOutputStream(), evidence.getClaim());

			return Arrays.equals(computedClaim, sentCompClaim);
		}

		private ProxyResponse joinMock(ProxyMessage msg) throws IOException {
			//SchnorrSignature sign = combineSignatures((UncombinedConfidentialResponse) res);
			//byte[] data = Arrays.copyOfRange(res.getPlainData(), res.getPlainData().length - 156, res.getPlainData().length);
			java.sql.Timestamp ts = new java.sql.Timestamp(System.currentTimeMillis());
			byte[] hash = computeHash(msg.toByteArray());
			//byte[] ts = Arrays.copyOfRange(data, 0, 91);
			//byte[] pubKey = Arrays.copyOfRange(data, 91, 124);
			//byte[] hash = Arrays.copyOfRange(data, 124, data.length);
			System.out.println("Device with id " + msg.getDeviceId() + " attested at " + ts);
			return ProxyResponse.newBuilder()
					.setPubKey(msg.getPubKey())
					.setTimestamp(ByteString.copyFrom(serialize(ts)))
					.setHash(ByteString.copyFrom(hash))
					.setType(ProxyResponse.ResponseType.JOIN)
					//.setSign(schnorrToProto(sign))
					.build();
		}

		private ProxyResponse timestampAttMock(ProxyMessage msg) throws IOException {
			System.out.println("Received attest timestamp request from device with id " + msg.getDeviceId());
			//byte[] data = Arrays.copyOfRange(res.getPlainData(), res.getPlainData().length - 124, res.getPlainData().length);
			java.sql.Timestamp ts = new java.sql.Timestamp(System.currentTimeMillis());
			//byte[] pubKey = Arrays.copyOfRange(data, 91, data.length);
			return ProxyResponse.newBuilder()
					.setPubKey(msg.getPubKey())
					.setTimestamp(ByteString.copyFrom(serialize(ts)))
					.setType(ProxyResponse.ResponseType.PREJOIN)
					//.setSign(schnorrToProto(sign))
					.build();
		}

		private ProxyResponse timestampAttMQTTMock(ProxyMessage msg) throws IOException {
			System.out.println("Received attest timestamp request from mqtt with id " + msg.getDeviceId());
			//byte[] data = Arrays.copyOfRange(res.getPlainData(), res.getPlainData().length - 124, res.getPlainData().length);
			java.sql.Timestamp ts = new java.sql.Timestamp(System.currentTimeMillis());
			//byte[] pubKey = Arrays.copyOfRange(data, 91, data.length);
			return ProxyResponse.newBuilder()
					.setTimestamp(ByteString.copyFrom(serialize(ts)))
					.setType(ProxyResponse.ResponseType.PREJOIN_MQTT)
					//.setSign(schnorrToProto(sign))
					.build();
		}

		private byte[] computeHash(byte[]... contents) {
			try {
				MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
				for (byte[] content : contents) {
					messageDigest.update(content);
				}
				return messageDigest.digest();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			return null;
		}
	}
}
