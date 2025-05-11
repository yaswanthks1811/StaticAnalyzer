package Bean;

import java.io.Serializable;

public class PEStaticInfo implements Serializable {
    private int magicNumber;
    private long entryPoint;
    private String entryPointSection = "UNKNOWN";
    private boolean digitallySigned;
    private long imageBase;
    private String subsystem = "UNKNOWN";
    private String imageFileCharacteristics = "";
    private String dllCharacteristics = "";
    private String timeStamp = "";
    private String tlsCallbacks = "None";
    private String clrVersion = "None";
    private int osVersionMajor;
    private int osVersionMinor;
    private int fileVersionMajor;
    private int fileVersionMinor;
    private int subsystemVersionMajor;
    private int subsystemVersionMinor;
    private int richHeaderOffset;
    private String xorkey;
    private String importHash = "";

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Static PE Info\n");
        sb.append("General\n");
        sb.append(String.format("Entrypoint:\t0x%X\n", entryPoint));
        sb.append(String.format("Entrypoint Section:\t%s\n", entryPointSection));
        sb.append(String.format("Digitally signed:\t%b\n", digitallySigned));
        sb.append(String.format("Imagebase:\t0x%X\n", imageBase));
        sb.append(String.format("Subsystem:\t%s\n", subsystem.toLowerCase()));
        sb.append(String.format("Image File Characteristics:\t%s\n", imageFileCharacteristics));
        sb.append(String.format("DLL Characteristics:\t%s\n", dllCharacteristics));
        sb.append(String.format("Time Stamp:\t%s\n", timeStamp));
        sb.append(String.format("TLS Callbacks:\t%s\n", tlsCallbacks));
        sb.append(String.format("CLR (.Net) Version:\t%s\n", clrVersion));
        sb.append(String.format("OS Version Major:\t%d\n", osVersionMajor));
        sb.append(String.format("OS Version Minor:\t%d\n", osVersionMinor));
        sb.append(String.format("File Version Major:\t%d\n", fileVersionMajor));
        sb.append(String.format("File Version Minor:\t%d\n", fileVersionMinor));
        sb.append(String.format("Subsystem Version Major:\t%d\n", subsystemVersionMajor));
        sb.append(String.format("Subsystem Version Minor:\t%d\n", subsystemVersionMinor));
        sb.append(String.format("Import Hash:\t%s\n", importHash));
        return sb.toString();
    }

    // Getters and setters
    public long getEntryPoint() {
        return entryPoint;
    }

    public void setEntryPoint(long entryPoint) {
        this.entryPoint = entryPoint;
    }

    public String getEntryPointSection() {
        return entryPointSection;
    }

    public void setEntryPointSection(String entryPointSection) {
        this.entryPointSection = entryPointSection;
    }

    public boolean isDigitallySigned() {
        return digitallySigned;
    }

    public void setDigitallySigned(boolean digitallySigned) {
        this.digitallySigned = digitallySigned;
    }

    public long getImageBase() {
        return imageBase;
    }

    public void setImageBase(long imageBase) {
        this.imageBase = imageBase;
    }

    public String getSubsystem() {
        return subsystem;
    }

    public void setSubsystem(String subsystem) {
        this.subsystem = subsystem;
    }

    public String getImageFileCharacteristics() {
        return imageFileCharacteristics;
    }

    public void setImageFileCharacteristics(String imageFileCharacteristics) {
        this.imageFileCharacteristics = imageFileCharacteristics;
    }

    public String getDllCharacteristics() {
        return dllCharacteristics;
    }

    public void setDllCharacteristics(String dllCharacteristics) {
        this.dllCharacteristics = dllCharacteristics;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getTlsCallbacks() {
        return tlsCallbacks;
    }

    public void setTlsCallbacks(String tlsCallbacks) {
        this.tlsCallbacks = tlsCallbacks;
    }

    public String getClrVersion() {
        return clrVersion;
    }

    public void setClrVersion(String clrVersion) {
        this.clrVersion = clrVersion;
    }

    public int getOsVersionMajor() {
        return osVersionMajor;
    }

    public void setOsVersionMajor(int osVersionMajor) {
        this.osVersionMajor = osVersionMajor;
    }

    public int getOsVersionMinor() {
        return osVersionMinor;
    }

    public void setOsVersionMinor(int osVersionMinor) {
        this.osVersionMinor = osVersionMinor;
    }

    public int getFileVersionMajor() {
        return fileVersionMajor;
    }

    public void setFileVersionMajor(int fileVersionMajor) {
        this.fileVersionMajor = fileVersionMajor;
    }

    public int getFileVersionMinor() {
        return fileVersionMinor;
    }

    public void setFileVersionMinor(int fileVersionMinor) {
        this.fileVersionMinor = fileVersionMinor;
    }

    public int getSubsystemVersionMajor() {
        return subsystemVersionMajor;
    }

    public void setSubsystemVersionMajor(int subsystemVersionMajor) {
        this.subsystemVersionMajor = subsystemVersionMajor;
    }

    public int getSubsystemVersionMinor() {
        return subsystemVersionMinor;
    }

    public void setSubsystemVersionMinor(int subsystemVersionMinor) {
        this.subsystemVersionMinor = subsystemVersionMinor;
    }

    public String getImportHash() {
        return importHash;
    }

    public void setImportHash(String importHash) {
        this.importHash = importHash;
    }

    public int getRichHeaderOffset() {
        return richHeaderOffset;
    }

    public void setRichHeaderOffset(int richHeaderOffset) {
        this.richHeaderOffset = richHeaderOffset;
    }

    public String getXorkey() {
        return xorkey;
    }

    public void setXorkey(String xorkey) {
        this.xorkey = xorkey;
    }
}
