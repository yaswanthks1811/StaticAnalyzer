package Analyzers;

import Utilities.Utils;
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

        int peHeaderOffset = Utils.readDWord(fileBytes, 0x3C);
        if (peHeaderOffset <= 0 || peHeaderOffset + 248 >= fileBytes.length) {
            throw new IllegalArgumentException("Invalid PE header offset");
        }

        // Check PE signature
        if (Utils.readDWord(fileBytes, peHeaderOffset) != 0x00004550) {
            throw new IllegalArgumentException("Invalid PE signature");
        }

        // Optional Header
        int optionalHeaderOffset = peHeaderOffset + 24;
        int magic = Utils.readWord(fileBytes, optionalHeaderOffset);
        boolean is64bit = (magic == 0x20B);

        // Get Export Table RVA and Size
        int exportTableRva = Utils.readDWord(fileBytes, optionalHeaderOffset + (is64bit ? 112 : 96));
        int exportTableSize = Utils.readDWord(fileBytes, optionalHeaderOffset + (is64bit ? 116 : 100));

        if (exportTableRva == 0 || exportTableSize == 0) {
            return exportsInfo; // No exports
        }

        // Convert RVA to file offset
        int exportTableOffset = Utils.rvaToOffset(fileBytes, peHeaderOffset, exportTableRva);
        if (exportTableOffset == -1) {
            return exportsInfo;
        }

        // Parse Export Directory
        int characteristics = Utils.readDWord(fileBytes, exportTableOffset);
        int timeDateStamp = Utils.readDWord(fileBytes, exportTableOffset + 4);
        int majorVersion = Utils.readWord(fileBytes, exportTableOffset + 8);
        int minorVersion = Utils.readWord(fileBytes, exportTableOffset + 10);
        int nameRva = Utils.readDWord(fileBytes, exportTableOffset + 12);
        int ordinalBase = Utils.readDWord(fileBytes, exportTableOffset + 16);
        int numberOfFunctions = Utils.readDWord(fileBytes, exportTableOffset + 20);
        int numberOfNames = Utils.readDWord(fileBytes, exportTableOffset + 24);
        int addressOfFunctionsRva = Utils.readDWord(fileBytes, exportTableOffset + 28);
        int addressOfNamesRva = Utils.readDWord(fileBytes, exportTableOffset + 32);
        int addressOfNameOrdinalsRva = Utils.readDWord(fileBytes, exportTableOffset + 36);

        // Get function addresses
        int functionsOffset = Utils.rvaToOffset(fileBytes, peHeaderOffset, addressOfFunctionsRva);
        int namesOffset = Utils.rvaToOffset(fileBytes, peHeaderOffset, addressOfNamesRva);
        int ordinalsOffset = Utils.rvaToOffset(fileBytes, peHeaderOffset, addressOfNameOrdinalsRva);

        if (functionsOffset == -1 || namesOffset == -1 || ordinalsOffset == -1) {
            return exportsInfo;
        }

        // Create map of ordinal to address
        Map<Integer, Long> ordinalToAddress = new TreeMap<>();
        for (int i = 0; i < numberOfFunctions; i++) {
            int functionRva = Utils.readDWord(fileBytes, functionsOffset + i * 4);
            if (functionRva != 0) { // Skip null entries
                ordinalToAddress.put(i + ordinalBase, (long) functionRva);
            }
        }

        // Create map of name to ordinal
        Map<String, Integer> nameToOrdinal = new TreeMap<>();
        for (int i = 0; i < numberOfNames; i++) {
            int namePtrRva = Utils.readDWord(fileBytes, namesOffset + i * 4);
            int nameOffset = Utils.rvaToOffset(fileBytes, peHeaderOffset, namePtrRva);
            if (nameOffset != -1) {
                String name = Utils.readNullTerminatedString(fileBytes, nameOffset);
                int ordinal = Utils.readWord(fileBytes, ordinalsOffset + i * 2);
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



}