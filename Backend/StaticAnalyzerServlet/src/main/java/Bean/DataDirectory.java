package Bean;

import java.io.Serializable;

public class DataDirectory implements Serializable {
    private int index;
    private String name;
    private int virtualAddress;
    private int size;
    private String section;

    public DataDirectory() {
    }

    public DataDirectory(int index, String name, int virtualAddress, int size, String section) {
        this.index = index;
        this.name = name;
        this.virtualAddress = virtualAddress;
        this.size = size;
        this.section = section;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getVirtualAddress() {
        return virtualAddress;
    }

    public void setVirtualAddress(int virtualAddress) {
        this.virtualAddress = virtualAddress;
    }

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public String getSection() {
        return section;
    }

    public void setSection(String section) {
        this.section = section;
    }
}
