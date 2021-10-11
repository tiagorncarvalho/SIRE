package sire.client;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.ExtractedResponse;
import confidential.ConfidentialExtractedResponse;
import confidential.ConfidentialMessage;
import confidential.client.ClientConfidentialityScheme;
import confidential.client.ServersResponseHandler;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.polynomial.Polynomial;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.*;

/**
 * @author robin
 */
public class PlainServersResponseHandler extends ServersResponseHandler {
	private final Map<byte[], ConfidentialMessage> responses;
	private final Map<ConfidentialMessage, Integer> responseHashes;
	private final Set<BigInteger> corruptedShareholders;
	private BigInteger field;
	private InterpolationStrategy interpolationStrategy;

	public PlainServersResponseHandler() {
		this.responses = new HashMap<>();
		this.responseHashes = new HashMap<>();
		this.corruptedShareholders = new HashSet<>();
	}

	@Override
	public void setClientConfidentialityScheme(ClientConfidentialityScheme confidentialityScheme) {
		super.setClientConfidentialityScheme(confidentialityScheme);
		this.field = confidentialityScheme.getField();
		this.interpolationStrategy = confidentialityScheme.getInterpolationStrategy();
	}

	@Override
	public ExtractedResponse extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
		ConfidentialMessage response;
		TOMMessage lastMsg = replies[lastReceived];
		Map<Integer, LinkedList<ConfidentialMessage>> msgs = new HashMap<>();
		for (TOMMessage msg : replies) {
			if (msg == null)
				continue;
			response = responses.get(msg.getContent());
			if (response == null) {
				logger.warn("Something went wrong while getting deserialized response from {}", msg.getSender());
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
				byte[][] confidentialData = null;

				if (firstMsg.getShares() != null) { // this response has secret data
					int numSecrets = firstMsg.getShares().length;
					ArrayList<LinkedList<VerifiableShare>> verifiableShares =
							new ArrayList<>(numSecrets);
					for (int i = 0; i < numSecrets; i++) {
						verifiableShares.add(new LinkedList<>());
					}
					confidentialData = new byte[numSecrets][];

					for (ConfidentialMessage confidentialMessage : msgList) {
						VerifiableShare[] sharesI =
								confidentialMessage.getShares();
						for (int i = 0; i < numSecrets; i++) {
							verifiableShares.get(i).add(sharesI[i]);
						}
					}

					byte[] shareData;
					Share[] shares;
					for (int i = 0; i < numSecrets; i++) {
						LinkedList<VerifiableShare> secretI = verifiableShares.get(i);
						shares = new Share[secretI.size()];
						Map<BigInteger, Commitment> commitmentsToCombine =
								new HashMap<>(secretI.size());
						shareData = secretI.getFirst().getSharedData();
						int k = 0;
						for (VerifiableShare verifiableShare : secretI) {
							shares[k] = verifiableShare.getShare();
							commitmentsToCombine.put(
									verifiableShare.getShare().getShareholder(),
									verifiableShare.getCommitments());
							k++;
						}
						Commitment commitment =
								commitmentScheme.combineCommitments(commitmentsToCombine);
						OpenPublishedShares secret = new OpenPublishedShares(shares, commitment, shareData);
						try {
							confidentialData[i] = combine(secret);
						} catch (SecretSharingException e) {
							return new ConfidentialExtractedResponse(lastMsg.getViewID(), plainData,
									confidentialData, e);
						}
					}
				}
				return new ConfidentialExtractedResponse(lastMsg.getViewID(), plainData, confidentialData);
			}
		}
		logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
		return null;
	}

	public byte[] combine(OpenPublishedShares openShares) throws SecretSharingException {
		Commitment commitments = openShares.getCommitments();
		BigInteger secretKeyAsNumber;
		Share[] shares = openShares.getShares();
		Share[] minimumShares = new Share[corruptedShareholders.size() < threshold ? threshold + 2 : threshold + 1];
		for (int i = 0, j = 0; i < shares.length && j < minimumShares.length; i++) {
			Share share = shares[i];
			if (!corruptedShareholders.contains(share.getShareholder()))
				minimumShares[j++] = share;
		}
		Polynomial polynomial = new Polynomial(field, minimumShares);
		if (polynomial.getDegree() != threshold) {
			minimumShares = new Share[threshold + 1];
			int counter = 0;

			commitmentScheme.startVerification(openShares.getCommitments());
			for (Share share : shares) {
				if (corruptedShareholders.contains(share.getShareholder()))
					continue;
				boolean valid = commitmentScheme.checkValidity(share, commitments);

				if (counter <= threshold && valid)
					minimumShares[counter++] = share;
				if (!valid)
					corruptedShareholders.add(share.getShareholder());
			}
			commitmentScheme.endVerification();
			if (counter <= threshold)
				throw new SecretSharingException("Not enough valid shares!");
			secretKeyAsNumber = interpolationStrategy.interpolateAt(BigInteger.ZERO, minimumShares);
		} else {
			secretKeyAsNumber = polynomial.getConstant();
		}

		return secretKeyAsNumber.toByteArray();
	}

	@Override
	public int compare(byte[] o1, byte[] o2) {
		ConfidentialMessage response1 = responses.computeIfAbsent(o1,
				ConfidentialMessage::deserialize);
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
		corruptedShareholders.clear();
	}
}
