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
import com.google.protobuf.Timestamp;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.math.ec.ECPoint;
import sire.membership.DeviceContext;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignature;
import sire.serverProxyUtils.*;

import static sire.messages.ProtoUtils.*;

import sire.messages.Messages.*;
import sire.schnorr.SchnorrSignatureScheme;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * @author robin
 */

public class SocketProxy implements Runnable {
	private static final int AES_KEY_LENGTH = 128;
	private final ConfidentialServiceProxy serviceProxy;
	private final ECPoint verifierPublicKey;
	private final SchnorrSignatureScheme signatureScheme;
	private final int proxyId;
	private final Object proxyLock;

	public SocketProxy(int proxyId) throws SireException{
		System.out.println("Proxy start!");
		this.proxyId = proxyId;

		try {
			serviceProxy = new ConfidentialServiceProxy(proxyId);
			proxyLock = new Object();
		} catch (SecretSharingException e) {
			throw new SireException("Failed to contact the distributed verifier", e);
		}
		System.out.println("Connection established!");
		try {
			BlockCipher aes = new AESEngine();

			signatureScheme = new SchnorrSignatureScheme();
		} catch (NoSuchAlgorithmException e) {
			throw new SireException("Failed to initialize cryptographic tools", e);
		}
		Response response;
		try {
			ProxyMessage msg = ProxyMessage.newBuilder()
					.setOperation(ProxyMessage.Operation.ATTEST_GET_PUBLIC_KEY)
					.build();
			byte[] b = msg.toByteArray();
			response = serviceProxy.invokeOrdered(b);//new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
		} catch (SecretSharingException e) {
			throw new SireException("Failed to obtain verifier's public key", e);
		}
		verifierPublicKey = signatureScheme.decodePublicKey(response.getPainData());

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
				ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
				ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

				while (!s.isClosed()) {
					Object o;
					while ((o = ois.readObject()) != null) {
						if (o instanceof ProxyMessage) {
							ProxyMessage msg = (ProxyMessage) o;
							if (msg.getOperation() == ProxyMessage.Operation.ATTEST_GET_PUBLIC_KEY) {
								oos.writeObject(SchnorrSignatureScheme.encodePublicKey(verifierPublicKey));
							} else {
								ProxyResponse result = runProxyMessage(msg);
								if (result != null)
									oos.writeObject(result);
							}
						}

					}
				}
			} catch (ClassNotFoundException | SecretSharingException | SireException e) {
				e.printStackTrace();
			} catch (IOException ignored) {}
		}

		private ProxyResponse runProxyMessage(ProxyMessage msg) throws IOException, SecretSharingException, ClassNotFoundException, SireException {
			Response res;
			if(msg.getOperation().toString().contains("GET") || msg.getOperation().toString().contains("VIEW"))
				res = serviceProxy.invokeUnordered(msg.toByteArray());
			else if(msg.getOperation() == ProxyMessage.Operation.ATTEST_TIMESTAMP)
				return timestampAtt(serviceProxy.invokeOrdered(msg.toByteArray()));
			else if(msg.getOperation() == ProxyMessage.Operation.MEMBERSHIP_JOIN)
				return join(serviceProxy.invokeOrdered(msg.toByteArray()));
			else {
				synchronized (proxyLock) {
					res = serviceProxy.invokeOrdered(msg.toByteArray());
				}
			}
			switch(msg.getOperation()) {
				case MAP_GET: return mapGet(res);
				case MAP_LIST: return mapList(res);
				case MEMBERSHIP_VIEW: return memberView(res);
				case EXTENSION_GET: return extGet(res);
				case POLICY_GET: return policyGet(res);
				case TIMESTAMP_GET: return timestampGet(res);
				default: return null;
			}
		}

		private ProxyResponse join(Response res) throws SireException {
			SchnorrSignature sign = combineSignatures(res);
			byte[] data = Arrays.copyOfRange(res.getPainData(), res.getPainData().length - 156, res.getPainData().length);
			byte[] ts = Arrays.copyOfRange(data, 0, 91);
			byte[] pubKey = Arrays.copyOfRange(data, 91, 124);
			byte[] hash = Arrays.copyOfRange(data, 124, data.length);
			return ProxyResponse.newBuilder()
					.setPubKey(ByteString.copyFrom(pubKey))
					.setTimestamp(ByteString.copyFrom(ts))
					.setHash(ByteString.copyFrom(hash))
					.setSign(schnorrToProto(sign))
					.build();
		}

		private ProxyResponse timestampAtt(Response res) throws SireException {
			SchnorrSignature sign = combineSignatures(res);
			byte[] data = Arrays.copyOfRange(res.getPainData(), res.getPainData().length - 124, res.getPainData().length);
			byte[] ts = Arrays.copyOfRange(data, 0, 91);
			byte[] pubKey = Arrays.copyOfRange(data, 91, data.length);
			return ProxyResponse.newBuilder()
					.setPubKey(ByteString.copyFrom(pubKey))
					.setTimestamp(ByteString.copyFrom(ts))
					.setSign(schnorrToProto(sign))
					.build();
		}

		private SchnorrSignature combineSignatures (Response res) throws SireException {
			PublicPartialSignature partialSignature;
			byte[] signs = Arrays.copyOfRange(res.getPainData(), 0, 199);
			try (ByteArrayInputStream bis = new ByteArrayInputStream(signs);
				 ObjectInput in = new ObjectInputStream(bis)) {
				partialSignature = PublicPartialSignature.deserialize(signatureScheme, in);
			} catch (IOException | ClassNotFoundException e) {
				throw new SireException("Failed to deserialize public data of partial signatures");
			}
			EllipticCurveCommitment signingKeyCommitment = partialSignature.getSigningKeyCommitment();
			EllipticCurveCommitment randomKeyCommitment = partialSignature.getRandomKeyCommitment();
			ECPoint randomPublicKey = partialSignature.getRandomPublicKey();
			VerifiableShare[] verifiableShares = res.getConfidentialData()[0];
			Share[] partialSignatures = new Share[verifiableShares.length];
			for (int i = 0; i < verifiableShares.length; i++) {
				partialSignatures[i] = verifiableShares[i].getShare();
			}

			if (randomKeyCommitment == null)
				throw new IllegalStateException("Random key commitment is null");

			byte[] data = Arrays.copyOfRange(res.getPainData(), 199, res.getPainData().length);

			try {
				BigInteger sigma = signatureScheme.combinePartialSignatures(
						serviceProxy.getCurrentF(),
						data,
						signingKeyCommitment,
						randomKeyCommitment,
						randomPublicKey,
						partialSignatures
				);
				return new SchnorrSignature(sigma.toByteArray(), verifierPublicKey.getEncoded(true),
						randomPublicKey.getEncoded(true));
			} catch (SecretSharingException e) {
				throw new SireException("Failed to combine partial signatures", e);
			}
		}

		private ProxyResponse timestampGet(Response res) {
			return null;
		}

		private ProxyResponse policyGet(Response res) throws IOException, ClassNotFoundException, SecretSharingException {
			byte[] tmp = res.getPainData();
			if (tmp != null) {
				return ProxyResponse.newBuilder()
						.setType(ProxyResponse.ResponseType.POLICY_GET)
						.setExtPolicy((String) deserialize(tmp))
						.build();
			} else {
				return ProxyResponse.newBuilder().build();
			}

		}

		private ProxyResponse extGet(Response res) throws IOException, ClassNotFoundException, SecretSharingException {
			byte[] tmp = res.getPainData();
			if (tmp != null) {
				return ProxyResponse.newBuilder()
						.setType(ProxyResponse.ResponseType.EXTENSION_GET)
						.setExtPolicy((String) deserialize(tmp))
						.build();
			} else {
				return ProxyResponse.newBuilder().build();
			}
		}

		private ProxyResponse memberView(Response res) throws IOException, ClassNotFoundException, SecretSharingException {
			byte[] tmp = res.getPainData();
			ProxyResponse.Builder prBuilder = ProxyResponse.newBuilder();
			if (tmp != null) {
				ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
				ObjectInputStream oin = new ObjectInputStream(bin);
				List<DeviceContext> members = (List<DeviceContext>) oin.readObject();
				for (DeviceContext d : members)
					if(d.isCertificateValid()) {
						prBuilder.addMembers(ProxyResponse.ProtoDeviceContext.newBuilder()
								.setDeviceId(d.getDeviceId())
								.setTime(Timestamp.newBuilder()
										.setSeconds(d.getLastPing().getTime() / 1000)
										.build())
								.setCertExpTime(Timestamp.newBuilder()
										.setSeconds(d.getCertExpTime().getTime() / 1000)
										.build())
								.build());
					} else {
						prBuilder.addMembers(ProxyResponse.ProtoDeviceContext.newBuilder()
								.setDeviceId(d.getDeviceId())
								.setTime(Timestamp.newBuilder()
										.setSeconds(d.getLastPing().getTime() / 1000)
										.build())
								.build());
					}

			}
			return prBuilder.build();
		}

		private ProxyResponse mapList(Response res) throws IOException, ClassNotFoundException, SecretSharingException {
			byte[] tmp = res.getPainData();
			ProxyResponse.Builder prBuilder = ProxyResponse.newBuilder();
			if (tmp != null) {
				ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
				ObjectInputStream oin = new ObjectInputStream(bin);
				ArrayList<byte[]> lst = (ArrayList<byte[]>) oin.readObject();
				for (byte[] b : lst)
					prBuilder.addList(ByteString.copyFrom(b));
			}
			return prBuilder.build();
		}

		private ProxyResponse mapGet(Response res) throws SecretSharingException {
			byte[] tmp = res.getPainData();
			if (tmp != null) {
				return ProxyResponse.newBuilder()
						.setValue(ByteString.copyFrom(tmp))
						.build();
			} else {
				return ProxyResponse.newBuilder().build();
			}
		}

		private void close() {
			synchronized (proxyLock) {
				serviceProxy.close();
			}
		}
	}
}
