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

package sire.device;

import sire.membership.DeviceContext;
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

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, ClassNotFoundException {

		String appId = "app1";
		String version = "1.0";
		byte[] claim = "measure1".getBytes();
		DeviceStub dummy = new DeviceStub();
		dummy.attest(appId, version, claim);
		Random rng = new Random(1L);
		int var = rng.nextInt();

		try {
			String key = "exampleKey" + var;
			String key2 = "exampleKey2" + var;
			ExampleObject value = new ExampleObject("exampleValue" + var);
			ExampleObject value2 = new ExampleObject("exampleValue2" + var);
			ExampleObject newValue = new ExampleObject("exampleNewValue" + var);

			System.out.println("Putting entry: " + key + " " + value.getValue());
			dummy.put(appId, key, serialize(value));
			ExampleObject aberration = (ExampleObject) deserialize(dummy.getData(appId, key));
			System.out.println("Getting entry: " + key + " Value: " + aberration.getValue());

			System.out.println("Putting entry: " + key2 + " " + value2.getValue());
			dummy.put(appId, key2, serialize(value2));
			System.out.print("Getting all entries: [");
			List<byte[]> res = dummy.getList(appId);
			for(byte[] b : res)
				System.out.print(((ExampleObject) deserialize(b)).getValue() + ",");
			System.out.println("]");

			System.out.println("Delete entry: " + key2);
			dummy.delete(appId, key2);

			System.out.print("Getting entry: " + key2 + " Value: ");
			byte[] arr = dummy.getData(appId, key2);
			if(arr == null)
				System.out.println("null");
			else
				System.out.println(Arrays.toString(arr));

			System.out.println("Cas, key: " + key + " oldValue: " + value.getValue() + " newValue: " + newValue.getValue());
			dummy.cas(appId, key, serialize(value), serialize(newValue));

			ExampleObject result = (ExampleObject) deserialize(dummy.getData(appId, key));

			System.out.println("Getting entry: " + key + " Value: " + result.getValue());

			System.out.println("Membership 1!");
			for(DeviceContext d : dummy.getView(appId))
				System.out.println(d.toString());
			dummy.ping(appId);
			System.out.println("Membership 2!");
			for(DeviceContext d : dummy.getView(appId))
				System.out.println(d.toString());
			/*dummy.leave(appId);
			System.out.println("Membership 3!");
			for(DeviceContext d : dummy.getView(appId))
				System.out.println(d.toString());*/
			System.out.println("Done!");

		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		} finally {
			dummy.leave(appId);
			dummy.close();
		}
	}
}
