package sire.attestation;

public class AttValueStore {
    private static AttValueStore instance;
    private byte[] mrEnclave = hexStringToByteArray("32881371352F14B2EE36C4D874F8C50BEEC1F34677A993CDFBC450EC79681105");
    private byte[] mrSigner = hexStringToByteArray("83D719E77DEACA1470F6BAF62A4D774303C899DB69020F9C70EE1DFC08C7CE9E");
    private int securityVersion = 0;
    private int productId = 0;
    byte[] wasmByteCodeHash = hexStringToByteArray("B1E76B758EC360BA1BEAB548D7D43E1989CC8AE3096399130F9476925B0FD03F");

    public static AttValueStore getInstance() {
        if(instance == null)
            instance = new AttValueStore();
        return instance;
    }



    public byte[] getMrEnclave() {
        return mrEnclave;
    }

    public byte[] getMrSigner() {
        return mrSigner;
    }

    public int getSecurityVersion() {
        return securityVersion;
    }

    public int getProductId() {
        return productId;
    }

    public byte[] getWasmByteCodeHash() {
        return wasmByteCodeHash;
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
