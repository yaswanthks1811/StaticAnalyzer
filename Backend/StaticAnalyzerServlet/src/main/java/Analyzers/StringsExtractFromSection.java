package Analyzers;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

public class StringsExtractFromSection {
    private final byte[] fileBytes;
    private String rdataStrings;
    private String dataStrings;
    private Map<String, String> sectionStrings;

    public StringsExtractFromSection(byte[] fileBytes) {
        if (fileBytes == null) {
            throw new IllegalArgumentException("File bytes cannot be null");
        }
        this.fileBytes = fileBytes;
        this.rdataStrings = "";
        this.dataStrings = "";
        this.sectionStrings = new HashMap<>();
        parseSection();
    }

    public void parseSection() {
        try {
            // Get PE header offset from DOS header
            int peOffset = ByteBuffer.wrap(fileBytes, 0x3C, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();

            // Verify PE signature
            if (peOffset + 4 > fileBytes.length ||
                    fileBytes[peOffset] != 'P' ||
                    fileBytes[peOffset + 1] != 'E' ||
                    fileBytes[peOffset + 2] != 0 ||
                    fileBytes[peOffset + 3] != 0) {
                throw new RuntimeException("Invalid PE signature");
            }

            // Get number of sections
            int numSections = ByteBuffer.wrap(fileBytes, peOffset + 6, 2)
                    .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;

            // Get size of optional header
            int optionalHeaderSize = ByteBuffer.wrap(fileBytes, peOffset + 20, 2)
                    .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;

            // Section headers start after PE header + optional header
            int sectionOffset = peOffset + 24 + optionalHeaderSize;

            StringBuilder rdataBuilder = new StringBuilder();
            StringBuilder dataBuilder = new StringBuilder();

            // Parse each section header
            for (int i = 0; i < numSections; i++) {
                int currentOffset = sectionOffset + (i * 40); // Each section header is 40 bytes

                // Read section name (8 bytes, null-terminated)
                String sectionName = readNullTerminatedString(fileBytes, currentOffset, 8);

                // Read section characteristics
                int characteristics = ByteBuffer.wrap(fileBytes, currentOffset + 36, 4)
                        .order(ByteOrder.LITTLE_ENDIAN).getInt();

                // Only process sections that contain initialized data
                if ((characteristics & 0x00000040) != 0) { // IMAGE_SCN_CNT_INITIALIZED_DATA
                    // Read section raw data pointer and size
                    int rawDataPtr = ByteBuffer.wrap(fileBytes, currentOffset + 20, 4)
                            .order(ByteOrder.LITTLE_ENDIAN).getInt();
                    int rawDataSize = ByteBuffer.wrap(fileBytes, currentOffset + 16, 4)
                            .order(ByteOrder.LITTLE_ENDIAN).getInt();

                    if (rawDataPtr > 0 && rawDataSize > 0 &&
                            rawDataPtr + rawDataSize <= fileBytes.length) {

                        byte[] sectionData = new byte[rawDataSize];
                        System.arraycopy(fileBytes, rawDataPtr, sectionData, 0, rawDataSize);

                        String extractedStrings = extractStringsAsSingleString(sectionData);
                        sectionName = sectionName.substring(1, sectionName.length() );
                        sectionStrings.put(sectionName, extractedStrings);

                        if (".rdata".equals(sectionName)) {
                            if (rdataBuilder.length() > 0) {
                                rdataBuilder.append("\n");
                            }
                            rdataBuilder.append(extractedStrings);
                        } else if (".data".equals(sectionName)) {
                            if (dataBuilder.length() > 0) {
                                dataBuilder.append("\n");
                            }
                            dataBuilder.append(extractedStrings);
                        }
                    }
                }
            }

            this.rdataStrings = rdataBuilder.toString();
            this.dataStrings = dataBuilder.toString();

        } catch (Exception e) {
            System.err.println("Error parsing PE sections: " + e.getMessage());
            throw new RuntimeException("Failed to parse PE sections", e);
        }
    }

    private String extractStringsAsSingleString(byte[] data) {
        StringBuilder result = new StringBuilder();
        StringBuilder currentString = new StringBuilder();

        for (byte b : data) {
            char c = (char) (b & 0xFF);
            if (c >= 32 && c <= 126) { // Printable ASCII
                currentString.append(c);
            } else {
                if (currentString.length() >= 4) { // Minimum string length
                    if (result.length() > 0) {
                        result.append("\n");
                    }
                    result.append(currentString);
                }
                currentString.setLength(0); // More efficient than creating new StringBuilder
            }
        }

        // Add the last string if we ended in the middle of one
        if (currentString.length() >= 4) {
            if (result.length() > 0) {
                result.append("\n");
            }
            result.append(currentString);
        }

        return result.toString();
    }

    private String readNullTerminatedString(byte[] data, int offset, int maxLength) {
        StringBuilder sb = new StringBuilder();
        int end = Math.min(offset + maxLength, data.length);

        for (int i = offset; i < end; i++) {
            if (data[i] == 0) break;
            sb.append((char) (data[i] & 0xFF));
        }

        return sb.toString().trim();
    }

    // Getters for the extracted strings
    public String getRdataStrings() {
        return rdataStrings;
    }

    public String getDataStrings() {
        return dataStrings;
    }

    public Map<String, String> getSectionStrings() {
        return new HashMap<>(sectionStrings); // Return a copy for immutability
    }

    // Helper method to print the strings
    public void printStrings() {
        System.out.println("=== .rdata Strings ===");
        System.out.println(rdataStrings.isEmpty() ? "No strings found" : rdataStrings);

        System.out.println("\n=== .data Strings ===");
        System.out.println(dataStrings.isEmpty() ? "No strings found" : dataStrings);
    }
}