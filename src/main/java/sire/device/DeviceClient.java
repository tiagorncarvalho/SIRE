package sire.device;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;
import java.util.Random;
/**
 * @author robin
 */
public class DeviceClient {
	static long initialTime;
	static long totalLatencyAvg;
	static long totalLatencyMin;
	static long totalLatencyMax;

	static long systemLatencyAvg;
	static long systemLatencyMin;
	static long systemLatencyMax;

	static long averageWaitTime;
	static int numWaiters;

	static Integer counter;
	static final Object lock = new Object();
	static int numClients;

	public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, ClassNotFoundException, InterruptedException {
		initialTime = System.nanoTime();
		totalLatencyAvg = 0;
		totalLatencyMin = Long.MAX_VALUE;
		totalLatencyMax = 0;
		systemLatencyAvg = 0;
		systemLatencyMin = Long.MAX_VALUE;
		systemLatencyMax = 0;
		averageWaitTime = 0;
		numWaiters = 0;
		counter = 0;
		numClients = 4000;

		for (int i = 0; i < numClients; i++) {
			new DeviceThread().start();
			Thread.sleep(450);
		}

		synchronized (lock) {
			lock.wait();
		}

		double totalAverage = (totalLatencyAvg / (float) numClients) / 1_000_000.0;
		long totalMax = totalLatencyMax / 1_000_000;
		long totalMin = totalLatencyMin / 1_000_000;

		double systemAverage = (systemLatencyAvg / (float) numClients) / 1_000_000.0;
		long systemMax = systemLatencyMax / 1_000_000;
		long systemMin = systemLatencyMin / 1_000_000;

		double waitAverage = (averageWaitTime / (float) numWaiters) / 1_000_000.0;

		long totalTime = System.nanoTime() - initialTime;

		System.out.println("=============================");
		System.out.printf("Total Lat Avg: %.3f ms\n", totalAverage);
		System.out.printf("Total Lat Min: %d ms\n", totalMin);
		System.out.printf("Total Lat Max: %d ms\n", totalMax);
		System.out.printf("System Lat Avg: %.3f ms\n", systemAverage);
		System.out.printf("System Lat Min: %d ms\n", systemMin);
		System.out.printf("System Lat Max: %d ms\n", systemMax);
		System.out.printf("Wait Time Avg: %.3f ms\n", waitAverage);
		System.out.printf("Percentage of waiting clients: %.1f (%d/%d)\n", (float) numWaiters/numClients * 100, numWaiters, numClients);
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
				long[] times = dummy.accessIntersection(appId, new Random().nextInt(0, 8) + "");
				t2 = System.nanoTime();
				long latency = t2 - t1;
				long systemLatency = latency - times[0] - times[1];
				if(times[1] != 0) {
					averageWaitTime += times[1];
					numWaiters++;
				}
				if (latency < totalLatencyMin)
					totalLatencyMin = latency;
				if (latency > totalLatencyMax)
					totalLatencyMax = latency;
				totalLatencyAvg += latency;

				if (systemLatency < systemLatencyMin)
					systemLatencyMin = systemLatency;
				if (systemLatency > systemLatencyMax)
					systemLatencyMax = systemLatency;
				systemLatencyAvg += systemLatency;

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
