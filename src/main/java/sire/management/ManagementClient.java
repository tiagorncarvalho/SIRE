package sire.management;


import sire.configuration.ExtensionType;

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
