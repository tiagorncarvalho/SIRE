package sire.configuration;

import groovy.lang.Script;
import java.io.Serializable;

public class Extension implements Serializable {
    String code;
    Script script;

    public Extension(String code, Script script) {
        this.code = code;
        this.script = script;
    }

    public Extension(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public Script getScript() {
        return script;
    }

    public void setScript(Script script) {
        this.script = script;
    }
}
