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
import sire.Operation;
import vss.secretsharing.VerifiableShare;

import java.io.*;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author robin
 */
public class SireServer implements ConfidentialSingleExecutable, RandomPolynomialListener {
	private final Logger logger = LoggerFactory.getLogger("sire");
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


	public static void main(String[] args) {
		if (args.length < 1) {
			System.out.println("Usage: sire.server.SireServer <server id>");
			System.exit(-1);
		}
		new SireServer(Integer.parseInt(args[0]));
	}

	public SireServer(int id) {
		this.id = id;
		lock = new ReentrantLock(true);
		requests = new TreeMap<>();
		data = new TreeMap<>();
		ConfidentialRecoverable cr = new ConfidentialRecoverable(id, this);
		serviceReplica = new ServiceReplica(id, cr, cr, null, null, null, null, cr);
		serverCommunicationSystem = serviceReplica.getServerCommunicationSystem();
		distributedPolynomialManager = cr.getDistributedPolynomialManager();
		distributedPolynomialManager.setRandomPolynomialListener(this);
	}

	@Override
	public ConfidentialMessage appExecuteOrdered(byte[] bytes, VerifiableShare[] verifiableShares,
												 MessageContext messageContext) {
		Operation op = Operation.getOperation(bytes[0]);
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
		}
		return null;
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
		logger.debug("Received random number polynomial with id {} in {} ms", context.getId(), delta);
		MessageContext messageContext = requests.get(context.getId());
		data.put(messageContext.getSender(), context.getPoint());
		logger.debug("Sending random number share to {}", messageContext.getSender());
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
			logger.error("Error while taking snapshot", e);
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
			logger.error("Error while installing snapshot", e);
		}
	}
}
