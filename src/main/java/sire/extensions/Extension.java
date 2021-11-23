package sire.extensions;

import java.io.Serializable;

public class Extension implements Serializable {
    String code;

    public Extension(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
