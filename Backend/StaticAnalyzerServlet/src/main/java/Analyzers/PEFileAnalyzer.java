package Analyzers;

import Bean.PEFileInfo;
import Utilities.Utils;

import java.io.IOException;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


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
        peFileInfo.setMd5Hash(Utils.calculateHash(fileBytes,"MD5"));
        peFileInfo.setSha1Hash(Utils.calculateHash(fileBytes,"SHA-1"));
        peFileInfo.setSha256Hash(Utils.calculateHash(fileBytes,"SHA-256"));
        peFileInfo.setSha512Hash(Utils.calculateHash(fileBytes,"SHA-512"));
        peFileInfo.setContentPreview(generateContentPreview());
        peFileInfo.setFileName(fileName);
    }

    private String detectFileType() {
        if (fileBytes.length > 0x40 &&
                fileBytes[0] == 0x4D && fileBytes[1] == 0x5A) { // MZ header

            int peOffset = Utils.readDWord(fileBytes,0x3C);
            if (peOffset + 4 < fileBytes.length &&
                    fileBytes[peOffset] == 0x50 && fileBytes[peOffset + 1] == 0x45) { // PE header
                int magic = Utils.readWord(fileBytes, peOffset + 24);

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



    public long getFileSize() {
        return fileBytes.length;
    }

}