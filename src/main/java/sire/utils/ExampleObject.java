package sire.utils;

import java.io.Serializable;
import java.util.Objects;

public class ExampleObject implements Serializable {
    final String value;

    public ExampleObject(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExampleObject that = (ExampleObject) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "ExampleObject{" +
                "value='" + value + '\'' +
                '}';
    }
}
