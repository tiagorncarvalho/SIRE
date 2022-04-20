package sire.proxy;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.ExtractedResponse;
import confidential.ConfidentialMessage;
import confidential.client.ClientConfidentialityScheme;
import confidential.client.ServersResponseHandler;
import vss.secretsharing.VerifiableShare;

import java.util.*;

/**
 * @author robin
 */
public class ServersResponseHandlerWithoutCombine extends ServersResponseHandler {
	private final Map<byte[], ConfidentialMessage> responses;
	private final Map<ConfidentialMessage, Integer> responseHashes;

	public ServersResponseHandlerWithoutCombine() {
		this.responses = new HashMap<>();
		this.responseHashes = new HashMap<>();
	}

	@Override
	public void setClientConfidentialityScheme(ClientConfidentialityScheme confidentialityScheme) {
		super.setClientConfidentialityScheme(confidentialityScheme);
	}

	@Override
	public ExtractedResponse extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
		TOMMessage lastMsg = replies[lastReceived];
		ConfidentialMessage response;
		Map<Integer, LinkedList<ConfidentialMessage>> msgs = new HashMap<>();
		for (TOMMessage msg : replies) {
			if (msg == null)
				continue;
			response = responses.get(msg.getContent());
			if (response == null) {
//				logger.warn("Something went wrong while getting deserialized response from {}", msg.getSender());
				continue;
			}
			int responseHash = responseHashes.get(response);

			LinkedList<ConfidentialMessage> msgList = msgs.computeIfAbsent(responseHash, k -> new LinkedList<>());
			msgList.add(response);
		}

		for (LinkedList<ConfidentialMessage> msgList : msgs.values()) {
			if (msgList.size() == sameContent) {
				ConfidentialMessage firstMsg = msgList.getFirst();
				byte[] plainData = firstMsg.getPlainData();
				VerifiableShare[][] allVerifiableShares = null;
				byte[][] sharedData = null;

				if (firstMsg.getShares() != null) { // this response has secret data
					int numSecrets = firstMsg.getShares().length;
					ArrayList<LinkedList<VerifiableShare>> verifiableShares =
							new ArrayList<>(numSecrets);
					for (int i = 0; i < numSecrets; i++) {
						verifiableShares.add(new LinkedList<>());
					}
					for (ConfidentialMessage confidentialMessage : msgList) {
						VerifiableShare[] sharesI =
								confidentialMessage.getShares();
						for (int i = 0; i < numSecrets; i++) {
							verifiableShares.get(i).add(sharesI[i]);
						}
					}

					allVerifiableShares = new VerifiableShare[numSecrets][];
					sharedData = new byte[numSecrets][];
					for (int i = 0; i < numSecrets; i++) {
						LinkedList<VerifiableShare> secretI = verifiableShares.get(i);
						sharedData[i] = secretI.getFirst().getSharedData();
						int k = 0;
						allVerifiableShares[i] = new VerifiableShare[secretI.size()];
						for (VerifiableShare verifiableShare : secretI) {
							allVerifiableShares[i][k] = verifiableShare;
							k++;
						}
					}
				}
				return new UncombinedConfidentialResponse(lastMsg.getViewID(), plainData, allVerifiableShares, sharedData);
			}
		}
//		logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
		return null;
	}

	@Override
	public int compare(byte[] o1, byte[] o2) {
		ConfidentialMessage response1 = responses.computeIfAbsent(o1, ConfidentialMessage::deserialize);
		ConfidentialMessage response2 = responses.computeIfAbsent(o2, ConfidentialMessage::deserialize);
		if (response1 == null && response2 == null)
			return 0;
		if (response1 == null)
			return 1;
		if (response2 == null)
			return -1;
		int hash1 = responseHashes.computeIfAbsent(response1, ConfidentialMessage::hashCode);
		int hash2 = responseHashes.computeIfAbsent(response2, ConfidentialMessage::hashCode);
		return hash1 - hash2;
	}

	@Override
	public void reset() {
		responses.clear();
		responseHashes.clear();
	}
}
