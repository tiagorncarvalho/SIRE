package sire.client;

import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import sire.Operation;
import vss.facade.SecretSharingException;

import java.math.BigInteger;

/**
 * @author robin
 */
public class SireClient {

	public static void main(String[] args) throws SecretSharingException {
		if (args.length < 1) {
			System.out.println("Usage: sire.client.SireClient <client id>");
			System.exit(-1);
		}
		int clientId = Integer.parseInt(args[0]);
		PlainServersResponseHandler serversResponseHandler = new PlainServersResponseHandler();
		ConfidentialServiceProxy serviceProxy = new ConfidentialServiceProxy(clientId, serversResponseHandler);

		Response response = serviceProxy.invokeOrdered(new byte[]{(byte) Operation.GET_RANDOM_NUMBER.ordinal()});
		System.out.println("Key: " + new BigInteger(response.getConfidentialData()[0]));

		serviceProxy.close();
	}

}
