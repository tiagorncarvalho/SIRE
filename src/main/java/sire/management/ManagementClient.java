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

package sire.management;


import sire.coordination.ExtensionType;

public class ManagementClient {
    public static void main(String[] args) {
        int proxyId = 1;
        ManagementStub stub = new ManagementStub(proxyId);
        try {
            System.out.println("Adding extension...");
            stub.addExtension("app1" + ExtensionType.EXT_GET + "exampleKey1", "print \"Hello World!\\n\"");
            System.out.println("Extension added!");
            System.out.println("Getting Extension, Key: " + "app1" + ExtensionType.EXT_GET.name() + "exampleKey1 Code: " +
                    stub.getExtension("app1" + ExtensionType.EXT_GET + "exampleKey1"));
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            stub.close();
        }
    }

}
