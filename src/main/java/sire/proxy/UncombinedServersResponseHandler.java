package sire.proxy;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.ServiceResponse;
import confidential.ConfidentialMessage;
import confidential.ExtractedResponse;
import confidential.client.ServersResponseHandler;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;

public class UncombinedServersResponseHandler extends ServersResponseHandler {

	@Override
	public ServiceResponse extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
		LinkedList<ConfidentialMessage> correctReplies = getCorrectReplies(replies, sameContent);

		if (correctReplies == null) {
			logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
			return null;
		}

		byte[] plainData = replies[lastReceived].getCommonContent();
		System.out.println("Plain data " + Arrays.toString(plainData));
		VerifiableShare[][] allSecretsShares = null;
		byte[][] allSharedData = null;
		if (correctReplies.getFirst().getShares() != null) { // this response has secret data
			OpenPublishedShares[] confidentialData = reconstructOpenPublishedShares(correctReplies);
			allSecretsShares = new VerifiableShare[confidentialData.length][];
			allSharedData = new byte[confidentialData.length][];
			for (int i = 0; i < confidentialData.length; i++) {
				OpenPublishedShares o = confidentialData[i];
				Commitment commitments = o.getCommitments();
				byte[] sharedData = o.getSharedData();
				Share[] shares = o.getShares();
				VerifiableShare[] vs = new VerifiableShare[shares.length];
				for (int j = 0; j < shares.length; j++) {
					vs[j] = new VerifiableShare(shares[j], commitments, sharedData);
				}
				allSecretsShares[i] = vs;
				allSharedData[i] = sharedData;
			}
		}
		return new UncombinedConfidentialResponse(plainData, allSecretsShares, allSharedData);
	}

	@Override
	protected Share reconstructShare(BigInteger shareholder, byte[] serializedShare) {
		return new Share(shareholder, new BigInteger(serializedShare));
	}
}