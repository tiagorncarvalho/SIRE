package sire.management;


import sire.extensions.ExtensionType;

public class ManagementClient {
    public static void main(String[] args) {
        int proxyId = 2;
        ManagementStub stub = new ManagementStub(proxyId);
        try {
            System.out.println("Adding extension...");
            stub.addExtension("app1", ExtensionType.EXT_GET, "exampleKey", "print \"Hello World!\\n\"");
            System.out.println("Extension added!");
            System.out.println("Getting Extension, Key: " + "app1" + ExtensionType.EXT_GET.name() + "exampleKey Code: " +
                    stub.getExtension("app1", ExtensionType.EXT_GET, "exampleKey").getCode());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            stub.close();
        }
    }

}
