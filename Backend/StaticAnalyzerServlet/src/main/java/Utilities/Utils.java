package Utilities;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {
    public static int rvaToOffset(byte[] fileBytes, int peHeaderOffset, int rva) {
        int numberOfSections = readWord(fileBytes, peHeaderOffset + 6);
        int sizeOfOptionalHeader = readWord(fileBytes, peHeaderOffset + 20);
        int sectionTableOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;

        for (int i = 0; i < numberOfSections; i++) {
            int sectionOffset = sectionTableOffset + (i * 40);
            if (sectionOffset + 40 > fileBytes.length)
                break;

            int virtualAddress = readDWord(fileBytes, sectionOffset + 12);
            int virtualSize = readDWord(fileBytes, sectionOffset + 8);
            int pointerToRawData = readDWord(fileBytes, sectionOffset + 20);
            int sizeOfRawData = readDWord(fileBytes, sectionOffset + 16);

            if (rva >= virtualAddress && rva < virtualAddress + virtualSize) {
                if (sizeOfRawData == 0) {
                    return rva;
                }
                return pointerToRawData + (rva - virtualAddress);
            }
        }
        return -1;
    }

    public static String readNullTerminatedString(byte[] bytes, int offset) {
        StringBuilder sb = new StringBuilder();
        while (offset < bytes.length && bytes[offset] != 0) {
            sb.append((char) bytes[offset]);
            offset++;
        }
        return sb.toString();
    }

    public static int readWord(byte[] bytes, int offset) {
        if (offset < 0 || offset + 2 > bytes.length)
            return 0;
        return ByteBuffer.wrap(bytes, offset, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
    }

    public static int readDWord(byte[] bytes, int offset) {
        if (offset < 0 || offset + 4 > bytes.length)
            return 0;
        return ByteBuffer.wrap(bytes, offset, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static long readQWord(byte[] bytes, int offset) {
        if (offset < 0 || offset + 8 > bytes.length)
            return 0;
        return ByteBuffer.wrap(bytes, offset, 8)
                .order(ByteOrder.LITTLE_ENDIAN).getLong();
    }
    public static String calculateHash(byte[] fileBytes ,String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hashBytes = digest.digest(fileBytes);
            return Utils.bytesToHex(hashBytes); // Using custom method
        } catch (NoSuchAlgorithmException e) {
            return "Algorithm " + algorithm + " not available";
        }
    }

}
