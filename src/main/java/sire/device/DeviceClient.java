package sire.device;

import sire.membership.DeviceContext;
import sire.membership.DeviceContext.DeviceType;
import sire.utils.ExampleObject;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static sire.messages.ProtoUtils.deserialize;
import static sire.messages.ProtoUtils.serialize;

/**
 * @author robin
 */
public class DeviceClient {
	static long initialTime;
	static long latencyAvg;
	static long latencyMin;
	static long latencyMax;
	static Integer counter;
	static final Object lock = new Object();
	static int numClients;

	public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, ClassNotFoundException, InterruptedException {
		initialTime = System.nanoTime();
		latencyAvg = 0;
		latencyMin = Long.MAX_VALUE;
		latencyMax = 0;
		counter = 0;
		numClients = 5000;

		for (int i = 0; i < numClients; i++) {
			new DeviceThread().start();
			Thread.sleep(720);
		}

		synchronized (lock) {
			lock.wait();
		}

		double average = (latencyAvg / (float) numClients) / 1_000_000.0;
		long max = latencyMax / 1_000_000;
		long min = latencyMin / 1_000_000;
		long totalTime = System.nanoTime() - initialTime;

		//double std = calculateStandardDeviation(latencies, average);
		System.out.println("=============================");
		System.out.printf("Avg: %.3f ms\n", average);
		//System.out.printf("Std: %.3f ms\n", std);
		System.out.printf("Min: %d ms\n", min);
		System.out.printf("Max: %d ms\n", max);
		System.out.printf("Duration: %d ms\n", totalTime);
		System.out.println("=============================");
	}

	private static class DeviceThread extends Thread {
		String appId = "app1";
		DeviceStub dummy;

		private DeviceThread() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, ClassNotFoundException {
			dummy = new DeviceStub();
			//dummy.attest(appId, type, version, claim);
		}

		@Override
		public void run() {
			try {

				long t2;
				long t1 = System.nanoTime();
				dummy.accessIntersection(appId, new Random().nextInt(0, 8) + "");
				t2 = System.nanoTime();
				long latency = t2 - t1;
				if (latency < latencyMin)
					latencyMin = latency;
				if (latency > latencyMax)
					latencyMax = latency;
				latencyAvg += latency;

			} catch (IOException | ClassNotFoundException | InterruptedException e) {
				e.printStackTrace();
			}

			synchronized (lock) {
				counter++;
				System.out.println(counter);
				if (counter >= numClients) {
					lock.notify();
				}
			}
		}
	}
}
