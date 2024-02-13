package sire.attestation;

public class EvidenceJSON {
    String type;

    String report_base64;
    int report_len;

    public EvidenceJSON(String type, String report_base64, int report_len) {
        this.type = type;
        this.report_base64 = report_base64;
        this.report_len = report_len;
    }

    public String getType() {
        return type;
    }

    public String getReport_base64() {
        return report_base64;
    }

    public int getReport_len() {
        return report_len;
    }
}