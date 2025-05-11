package Analyzers;

import Bean.PEFileInfo;

import java.io.IOException;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static Analyzers.PEInfoParser.readWord;

public class PEFileAnalyzer implements Serializable {
    PEFileInfo peFileInfo = new PEFileInfo();
    private String fileName;
    private byte[] fileBytes;

    public PEFileAnalyzer(byte[] fileBytes,String filename) throws IOException {
        this.fileName = filename;
        this.fileBytes = fileBytes;
        analyze();
    }
    public PEFileInfo getPEFileInfo() {
        return peFileInfo;
    }

    private void analyze() {
        peFileInfo.setFileType(detectFileType());
        peFileInfo.setFileSize(fileBytes.length);
        peFileInfo.setEntropy(calculateEntropy());
        peFileInfo.setMd5Hash(calculateHash("MD5"));
        peFileInfo.setSha1Hash(calculateHash("SHA-1"));
        peFileInfo.setSha256Hash(calculateHash("SHA-256"));
        peFileInfo.setSha512Hash(calculateHash("SHA-512"));
        peFileInfo.setContentPreview(generateContentPreview());
    }

    private String detectFileType() {
        if (fileBytes.length > 0x40 &&
                fileBytes[0] == 0x4D && fileBytes[1] == 0x5A) { // MZ header

            int peOffset = readDWord(0x3C);
            if (peOffset + 4 < fileBytes.length &&
                    fileBytes[peOffset] == 0x50 && fileBytes[peOffset + 1] == 0x45) { // PE header
                int magic = readWord(fileBytes, peOffset + 24);

                // Validate magic number
                if (magic != 0x10B && magic != 0x20B) {
                    throw new IllegalArgumentException("Invalid optional header magic number: 0x" +
                            Integer.toHexString(magic).toUpperCase());
                }

                boolean is64bit = (magic == 0x20B);

                if (is64bit) {
                    return "PE32+ executable " ;
                } else {

                    return "PE32 executable ";
                }
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

}