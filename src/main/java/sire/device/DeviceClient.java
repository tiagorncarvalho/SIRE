package sire.device;

import sire.serverProxyUtils.DeviceContext;
import sire.serverProxyUtils.DeviceContext.DeviceType;
import sire.utils.ExampleObject;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;
import java.util.List;

import static sire.messages.ProtoUtils.deserialize;
import static sire.messages.ProtoUtils.serialize;

/**
 * @author robin
 */
public class DeviceClient {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		if (args.length < 1) {
			System.out.println("Usage: sire.attester.AttesterClient <attester id>");
			System.exit(-1);
		}
		String attesterId = args[0];
		String appId = "app1";
		String waTZVersion = "1.0";
		DeviceType type = DeviceType.MOTIONSENSOR;
		byte[] claim = "measure1".getBytes();
		DeviceStub dummy = new DeviceStub();
		dummy.attest(appId, attesterId, type, waTZVersion, claim);

		try {
			String key = "exampleKey" + attesterId;
			String key2 = "exampleKey2" + attesterId;
			ExampleObject value = new ExampleObject("exampleValue" + attesterId);
			ExampleObject value2 = new ExampleObject("exampleValue2" + attesterId);
			ExampleObject newValue = new ExampleObject("exampleNewValue" + attesterId);

			System.out.println("Putting entry: " + key + " " + value.getValue());
			dummy.put(attesterId, appId, key, serialize(value));
			ExampleObject aberration = (ExampleObject) deserialize(dummy.getData(attesterId, appId, key));
			System.out.println("Getting entry: " + key + " Value: " + aberration.getValue());

			System.out.println("Putting entry: " + key2 + " " + value2.getValue());
			dummy.put(attesterId, appId, key2, serialize(value2));
			System.out.print("Getting all entries: [");
			List<byte[]> res = dummy.getList(attesterId, appId);
			for(byte[] b : res)
				System.out.print(((ExampleObject) deserialize(b)).getValue() + ",");
			System.out.println("]");

			System.out.println("Delete entry: " + key2);
			dummy.delete(attesterId, appId, key2);

			System.out.print("Getting entry: " + key2 + " Value: ");
			byte[] arr = dummy.getData(attesterId, appId, key2);
			if(arr == null)
				System.out.println("null");
			else
				System.out.println(Arrays.toString(arr));

			System.out.println("Cas, key: " + key + " oldValue: " + value.getValue() + " newValue: " + newValue.getValue());
			dummy.cas(attesterId, appId, key, serialize(value), serialize(newValue));

			ExampleObject result = (ExampleObject) deserialize(dummy.getData(attesterId, appId, key));

			System.out.println("Getting entry: " + key + " Value: " + result.getValue());

			for(DeviceContext d : dummy.getView(attesterId, appId))
				System.out.println(d.toString());
			dummy.ping(appId, attesterId);
			for(DeviceContext d : dummy.getView(attesterId, appId))
				System.out.println(d.toString());
			/*dummy.leave(appId, attesterId);
			for(DeviceContext d : dummy.getView(attesterId, appId))
				System.out.println(d.toString());*/
			System.out.println("Done!");

		} catch (IOException | ClassNotFoundException /*| InterruptedException*/ e) {
			e.printStackTrace();
		} finally {
			dummy.close();
		}
	}
}
