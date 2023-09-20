package sire.proxy;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.ServiceResponse;
import confidential.ConfidentialMessage;
import confidential.ExtractedResponse;
import confidential.client.ServersResponseHandler;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;

import java.math.BigInteger;
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
		OpenPublishedShares[] confidentialData = null;

		if (correctReplies.getFirst().getShares() != null) { // this response has secret data
			try {
				confidentialData = reconstructOpenPublishedShares(correctReplies);
			} catch (SecretSharingException e) {
				return new ExtractedResponse(plainData, confidentialData, e);
			}
		}
		return new ExtractedResponse(plainData, confidentialData);
	}

	@Override
	protected Share reconstructShare(BigInteger shareholder, byte[] serializedShare) {
		return new Share(shareholder, new BigInteger(serializedShare));
	}
}