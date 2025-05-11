package Bean;

import java.io.Serializable;

public class Exports implements Serializable {
    private String name;
    private int ordinal;
    private long address;

    public Exports() {
    }

    public Exports(String name, int ordinal, long address) {
        this.name = name;
        this.ordinal = ordinal;
        this.address = address;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getOrdinal() {
        return ordinal;
    }

    public void setOrdinal(int ordinal) {
        this.ordinal = ordinal;
    }

    public long getAddress() {
        return address;
    }

    public void setAddress(long address) {
        this.address = address;
    }
}
