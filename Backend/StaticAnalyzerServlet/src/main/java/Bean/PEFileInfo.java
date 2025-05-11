package Bean;

import java.io.Serializable;

public class PEFileInfo implements Serializable {
    private String fileName;
    private long fileSize;
    private String fileType;
    private double entropy;
    private String md5Hash;
    private String sha1Hash;
    private String sha256Hash;
    private String sha512Hash;
    private String contentPreview;
    private String machine;

    public PEFileInfo() {

    }

    public PEFileInfo(String fileName, long fileSize, String fileType,
                      double entropy, String md5Hash, String sha1Hash,
                      String sha256Hash, String sha512Hash,  String contentPreview) {
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.fileType = fileType;
        this.entropy = entropy;
        this.md5Hash = md5Hash;
        this.sha1Hash = sha1Hash;
        this.sha256Hash = sha256Hash;
        this.sha512Hash = sha512Hash;
        this.contentPreview = contentPreview;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    public String getFileType() {
        return fileType;
    }

    public void setFileType(String fileType) {
        this.fileType = fileType;
    }

    public double getEntropy() {
        return entropy;
    }

    public void setEntropy(double entropy) {
        this.entropy = entropy;
    }

    public String getMd5Hash() {
        return md5Hash;
    }

    public void setMd5Hash(String md5Hash) {
        this.md5Hash = md5Hash;
    }

    public String getSha1Hash() {
        return sha1Hash;
    }

    public void setSha1Hash(String sha1Hash) {
        this.sha1Hash = sha1Hash;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public void setSha256Hash(String sha256Hash) {
        this.sha256Hash = sha256Hash;
    }

    public String getSha512Hash() {
        return sha512Hash;
    }

    public void setSha512Hash(String sha512Hash) {
        this.sha512Hash = sha512Hash;
    }

    public String getContentPreview() {
        return contentPreview;
    }

    public void setContentPreview(String contentPreview) {
        this.contentPreview = contentPreview;
    }


}
