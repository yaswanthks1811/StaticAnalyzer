package Analyzers;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class PEExportsParser {


    public static class PEExportsInfo {
        private final List<ExportEntry> exports = new ArrayList<>();

        public void addExport(String name, int ordinal, long address) {
            exports.add(new ExportEntry(name, ordinal, address));
        }

        public List<ExportEntry> getExports() {
            return exports;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Exports\n");
            sb.append(String.format("%-30s\t%-8s\t%s\n", "Name", "Ordinal", "Address"));

            // Sort by ordinal if needed
            exports.sort((a, b) -> Integer.compare(a.getOrdinal(), b.getOrdinal()));

            for (ExportEntry entry : exports) {
                sb.append(String.format("%-30s\t%-8d\t0x%X\n",
                        entry.getName(),
                        entry.getOrdinal(),
                        entry.getAddress()));
            }
            return sb.toString();
        }

        private static class ExportEntry {
            private String name;
            private int ordinal;
            private long address;

            public int getOrdinal() {
                return ordinal;
            }

            public String getName() {
                return name;
            }

            public long getAddress() {
                return address;
            }



            public ExportEntry(String name, int ordinal, long address) {
                this.name = name;
                this.ordinal = ordinal;
                this.address = address;
            }
        }
    }

    public PEExportsInfo parse(byte[] fileBytes) throws Exception {
        return analyzeExports(fileBytes);
    }

    private PEExportsInfo analyzeExports(byte[] fileBytes) {
        PEExportsInfo exportsInfo = new PEExportsInfo();

        // Check MZ header
        if (fileBytes.length < 2 || fileBytes[0] != 'M' || fileBytes[1] != 'Z') {
            throw new IllegalArgumentException("Not a valid PE file");
        }

        int peHeaderOffset = readDword(fileBytes, 0x3C);
        if (peHeaderOffset <= 0 || peHeaderOffset + 248 >= fileBytes.length) {
            throw new IllegalArgumentException("Invalid PE header offset");
        }

        // Check PE signature
        if (readDword(fileBytes, peHeaderOffset) != 0x00004550) {
            throw new IllegalArgumentException("Invalid PE signature");
        }

        // Optional Header
        int optionalHeaderOffset = peHeaderOffset + 24;
        int magic = readWord(fileBytes, optionalHeaderOffset);
        boolean is64bit = (magic == 0x20B);

        // Get Export Table RVA and Size
        int exportTableRva = readDword(fileBytes, optionalHeaderOffset + (is64bit ? 112 : 96));
        int exportTableSize = readDword(fileBytes, optionalHeaderOffset + (is64bit ? 116 : 100));

        if (exportTableRva == 0 || exportTableSize == 0) {
            return exportsInfo; // No exports
        }

        // Convert RVA to file offset
        int exportTableOffset = rvaToOffset(fileBytes, peHeaderOffset, exportTableRva);
        if (exportTableOffset == -1) {
            return exportsInfo;
        }

        // Parse Export Directory
        int characteristics = readDword(fileBytes, exportTableOffset);
        int timeDateStamp = readDword(fileBytes, exportTableOffset + 4);
        int majorVersion = readWord(fileBytes, exportTableOffset + 8);
        int minorVersion = readWord(fileBytes, exportTableOffset + 10);
        int nameRva = readDword(fileBytes, exportTableOffset + 12);
        int ordinalBase = readDword(fileBytes, exportTableOffset + 16);
        int numberOfFunctions = readDword(fileBytes, exportTableOffset + 20);
        int numberOfNames = readDword(fileBytes, exportTableOffset + 24);
        int addressOfFunctionsRva = readDword(fileBytes, exportTableOffset + 28);
        int addressOfNamesRva = readDword(fileBytes, exportTableOffset + 32);
        int addressOfNameOrdinalsRva = readDword(fileBytes, exportTableOffset + 36);

        // Get function addresses
        int functionsOffset = rvaToOffset(fileBytes, peHeaderOffset, addressOfFunctionsRva);
        int namesOffset = rvaToOffset(fileBytes, peHeaderOffset, addressOfNamesRva);
        int ordinalsOffset = rvaToOffset(fileBytes, peHeaderOffset, addressOfNameOrdinalsRva);

        if (functionsOffset == -1 || namesOffset == -1 || ordinalsOffset == -1) {
            return exportsInfo;
        }

        // Create map of ordinal to address
        Map<Integer, Long> ordinalToAddress = new TreeMap<>();
        for (int i = 0; i < numberOfFunctions; i++) {
            int functionRva = readDword(fileBytes, functionsOffset + i * 4);
            if (functionRva != 0) { // Skip null entries
                ordinalToAddress.put(i + ordinalBase, (long) functionRva);
            }
        }

        // Create map of name to ordinal
        Map<String, Integer> nameToOrdinal = new TreeMap<>();
        for (int i = 0; i < numberOfNames; i++) {
            int namePtrRva = readDword(fileBytes, namesOffset + i * 4);
            int nameOffset = rvaToOffset(fileBytes, peHeaderOffset, namePtrRva);
            if (nameOffset != -1) {
                String name = readNullTerminatedString(fileBytes, nameOffset);
                int ordinal = readWord(fileBytes, ordinalsOffset + i * 2);
                nameToOrdinal.put(name, ordinal + ordinalBase);
            }
        }

        // Combine the information
        nameToOrdinal.forEach((name, ordinal) -> {
            if (ordinalToAddress.containsKey(ordinal)) {
                exportsInfo.addExport(name, ordinal, ordinalToAddress.get(ordinal));
            }
        });

        // Add exports without names (exported by ordinal only)
        ordinalToAddress.forEach((ordinal, address) -> {
            if (!nameToOrdinal.containsValue(ordinal)) {
                exportsInfo.addExport("", ordinal, address);
            }
        });

        return exportsInfo;
    }


    private int rvaToOffset(byte[] fileBytes, int peHeaderOffset, int rva) {
        int numberOfSections = readWord(fileBytes, peHeaderOffset + 6);
        int sizeOfOptionalHeader = readWord(fileBytes, peHeaderOffset + 20);
        int sectionTableOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;

        for (int i = 0; i < numberOfSections; i++) {
            int sectionOffset = sectionTableOffset + (i * 40);
            if (sectionOffset + 40 > fileBytes.length)
                break;

            int virtualAddress = readDword(fileBytes, sectionOffset + 12);
            int virtualSize = readDword(fileBytes, sectionOffset + 8);
            int pointerToRawData = readDword(fileBytes, sectionOffset + 20);
            int sizeOfRawData = readDword(fileBytes, sectionOffset + 16);

            if (rva >= virtualAddress && rva < virtualAddress + virtualSize) {
                if (sizeOfRawData == 0) {
                    return rva;
                }
                return pointerToRawData + (rva - virtualAddress);
            }
        }
        return -1;
    }

    private String readNullTerminatedString(byte[] bytes, int offset) {
        StringBuilder sb = new StringBuilder();
        while (offset < bytes.length && bytes[offset] != 0) {
            sb.append((char) bytes[offset]);
            offset++;
        }
        return sb.toString();
    }

    private static int readWord(byte[] bytes, int offset) {
        if (offset < 0 || offset + 2 > bytes.length)
            return 0;
        return ByteBuffer.wrap(bytes, offset, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
    }

    private static int readDword(byte[] bytes, int offset) {
        if (offset < 0 || offset + 4 > bytes.length)
            return 0;
        return ByteBuffer.wrap(bytes, offset, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
    }


}