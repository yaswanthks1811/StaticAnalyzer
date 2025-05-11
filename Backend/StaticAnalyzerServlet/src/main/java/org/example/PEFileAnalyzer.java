package org.example;

import Bean.PEFileInfo;

import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PEFileAnalyzer implements Serializable {
    PEFileInfo peFileInfo = new PEFileInfo();
    private String fileName;
    private byte[] fileBytes;
    private String fileType;
    private double entropy;
    private String md5Hash;
    private String sha1Hash;
    private String sha256Hash;
    private String sha512Hash;
    private String contentPreview;

    public PEFileAnalyzer(byte[] fileBytes,String filename) throws IOException {
        this.fileName = filename;
        this.fileBytes = fileBytes;
        analyze();
    }
    public PEFileInfo getPEFileInfo() {
        return peFileInfo;
    }

    private void analyze() {
        this.fileType = detectFileType();
        this.entropy = calculateEntropy();
        this.md5Hash = calculateHash("MD5");
        this.sha1Hash = calculateHash("SHA-1");
        this.sha256Hash = calculateHash("SHA-256");
        this.sha512Hash = calculateHash("SHA-512");
        this.contentPreview = generateContentPreview();
        peFileInfo.setFileType(detectFileType());
        peFileInfo.setFileSize(fileBytes.length);
        peFileInfo.setEntropy(entropy);
        peFileInfo.setMd5Hash(md5Hash);
        peFileInfo.setSha1Hash(sha1Hash);
        peFileInfo.setSha256Hash(sha256Hash);
        peFileInfo.setSha512Hash(sha512Hash);
        peFileInfo.setContentPreview(contentPreview);
    }

    private String detectFileType() {
        if (fileBytes.length > 0x40 &&
                fileBytes[0] == 0x4D && fileBytes[1] == 0x5A) { // MZ header

            int peOffset = readDWord(0x3C);
            if (peOffset + 4 < fileBytes.length &&
                    fileBytes[peOffset] == 0x50 && fileBytes[peOffset + 1] == 0x45) { // PE header

                return "PE32 executable (GUI) Intel 80386, for MS Windows";
            }
            return "DOS executable";
        }
        return "Unknown file type";
    }

    private double calculateEntropy() {
        if (fileBytes.length == 0)
            return 0.0;

        int[] frequency = new int[256];
        for (byte b : fileBytes) {
            frequency[b & 0xFF]++;
        }

        double entropy = 0.0;
        for (int count : frequency) {
            if (count == 0)
                continue;
            double probability = (double) count / fileBytes.length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }

    private String calculateHash(String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hashBytes = digest.digest(fileBytes);
            return bytesToHex(hashBytes); // Using custom method
        } catch (NoSuchAlgorithmException e) {
            return "Algorithm " + algorithm + " not available";
        }
    }

    // Custom hex conversion method for Java 8+
    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String generateContentPreview() {
        StringBuilder preview = new StringBuilder();
        int previewLength = Math.min(128, fileBytes.length);

        for (int i = 0; i < previewLength; i++) {
            if (fileBytes[i] >= 32 && fileBytes[i] < 127) {
                preview.append((char) fileBytes[i]);
            } else {
                preview.append('.');
            }
        }
        return preview.toString();
    }

    private int readDWord(int offset) {
        if (offset + 4 > fileBytes.length)
            return 0;
        return Byte.toUnsignedInt(fileBytes[offset]) |
                (Byte.toUnsignedInt(fileBytes[offset + 1]) << 8) |
                (Byte.toUnsignedInt(fileBytes[offset + 2]) << 16) |
                (Byte.toUnsignedInt(fileBytes[offset + 3]) << 24);
    }


    public long getFileSize() {
        return fileBytes.length;
    }

    public String getFileType() {
        return fileType;
    }

    public double getEntropy() {
        return entropy;
    }

    public String getMd5Hash() {
        return md5Hash;
    }

    public String getSha1Hash() {
        return sha1Hash;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public String getSha512Hash() {
        return sha512Hash;
    }

    public String getContentPreview() {
        return contentPreview;
    }

    @Override
    public String toString() {
        return String.format(
                "File name: %s\n" +
                        "File size: %d bytes\n" +
                        "File type: %s\n" +
                        "Entropy (8bit): %.15f\n" +
                        "MD5: %s\n" +
                        "SHA1: %s\n" +
                        "SHA256: %s\n" +
                        "SHA512: %s\n" +
                        "File Content Preview: %s",
                 getFileSize(), getFileType(), getEntropy(),
                getMd5Hash(), getSha1Hash(), getSha256Hash(), getSha512Hash(),
                getContentPreview());
    }
}