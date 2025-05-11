package org.example;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PEResourceAnalyzer implements Serializable {

    private final byte[] fileBytes;
    private final List<ResourceEntry> resources = new ArrayList<>();
    private int resourceSectionOffset = -1;
    private int resourceSectionRva;
    private int resourceSectionSize;
    private static final Map<Integer, String> RESOURCE_TYPES = new HashMap<>();

    static {
        RESOURCE_TYPES.put(1, "RT_CURSOR");
        RESOURCE_TYPES.put(2, "RT_BITMAP");
        RESOURCE_TYPES.put(3, "RT_ICON");
        RESOURCE_TYPES.put(4, "RT_MENU");
        RESOURCE_TYPES.put(5, "RT_DIALOG");
        RESOURCE_TYPES.put(6, "RT_STRING");
        RESOURCE_TYPES.put(7, "RT_FONTDIR");
        RESOURCE_TYPES.put(8, "RT_FONT");
        RESOURCE_TYPES.put(9, "RT_ACCELERATOR");
        RESOURCE_TYPES.put(10, "RT_RCDATA");
        RESOURCE_TYPES.put(11, "RT_MESSAGETABLE");
        RESOURCE_TYPES.put(12, "RT_GROUP_CURSOR");
        RESOURCE_TYPES.put(14, "RT_GROUP_ICON");
        RESOURCE_TYPES.put(16, "RT_VERSION");
        RESOURCE_TYPES.put(17, "RT_DLGINCLUDE");
        RESOURCE_TYPES.put(19, "RT_PLUGPLAY");
        RESOURCE_TYPES.put(20, "RT_VXD");
        RESOURCE_TYPES.put(21, "RT_ANICURSOR");
        RESOURCE_TYPES.put(22, "RT_ANIICON");
        RESOURCE_TYPES.put(23, "RT_HTML");
        RESOURCE_TYPES.put(24, "RT_MANIFEST");
    }

    public PEResourceAnalyzer(byte[] fileBytes) {
        this.fileBytes = fileBytes;
        parseResources();
    }

    private void parseResources() {
        // Check MZ header
        if (fileBytes.length < 2 || fileBytes[0] != 'M' || fileBytes[1] != 'Z') {
            System.err.println("Error: Not a valid PE file (missing MZ header)");
            return;
        }

        int peHeaderOffset = readDword(0x3C);
        if (peHeaderOffset <= 0 || peHeaderOffset + 248 >= fileBytes.length) {
            System.err.println("Invalid PE header offset");
            return;
        }

        // Check PE signature
        if (readDword(peHeaderOffset) != 0x00004550) {
            System.err.println("Invalid PE signature");
            return;
        }
        int optionalHeaderMagic = ByteBuffer.wrap(fileBytes, peHeaderOffset + 24, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        boolean is64Bit = (optionalHeaderMagic == 0x20B);

        // 3. Calculate data directory offset (32-bit: +96, 64-bit: +112)
        int dataDirOffset = peHeaderOffset + 24 + (is64Bit ? 112 : 96);

        this.resourceSectionRva = readDword(dataDirOffset + (2 * 8));
        this.resourceSectionSize = readDword(dataDirOffset + (2 * 8) + 4);

        if (resourceSectionRva == 0 || resourceSectionSize == 0) {
            System.err.println("No resource section found");
            return;
        }

        this.resourceSectionOffset = findSectionOffset(resourceSectionRva);
        if (resourceSectionOffset == -1) {
            System.err.println("Could not locate resource section in file");
            return;
        }

        parseResourceDirectory(resourceSectionOffset, 0, "");
    }

    private int findSectionOffset(int rva) {
        int peHeaderOffset = readDword(0x3C);
        int numSections = readWord(peHeaderOffset + 6);
        int optionalHeaderSize = readWord(peHeaderOffset + 20);
        int sectionTableOffset = peHeaderOffset + 24 + optionalHeaderSize;

        for (int i = 0; i < numSections; i++) {
            int sectionOffset = sectionTableOffset + (i * 40);
            if (sectionOffset + 40 > fileBytes.length) {
                System.err.println("Section table entry out of bounds");
                break;
            }

            int virtualAddress = readDword(sectionOffset + 12);
            int virtualSize = readDword(sectionOffset + 8);
            int pointerToRawData = readDword(sectionOffset + 20);
            int sizeOfRawData = readDword(sectionOffset + 16);

            if (rva >= virtualAddress && rva < virtualAddress + virtualSize) {
                if (sizeOfRawData == 0) {
                    return rva;
                }
                return pointerToRawData + (rva - virtualAddress);
            }
        }
        return -1;
    }

    private void parseResourceDirectory(int offset, int level, String path) {
        if (offset < 0 || offset + 16 >= fileBytes.length) {
            System.err.println("Invalid directory offset: 0x" + Integer.toHexString(offset));
            return;
        }

        int numberOfNamedEntries = readWord(offset + 12);
        int numberOfIdEntries = readWord(offset + 14);
        int totalEntries = numberOfNamedEntries + numberOfIdEntries;

        int entryOffset = offset + 16;
        for (int i = 0; i < totalEntries; i++) {
            if (entryOffset + 8 >= fileBytes.length) {
                System.err.println("Invalid entry offset: 0x" + Integer.toHexString(entryOffset));
                break;
            }

            int nameId = readDword(entryOffset);
            int dataOffset = readDword(entryOffset + 4);

            if ((nameId & 0x80000000) != 0) {
                int nameOffset = nameId & 0x7FFFFFFF;
                String name = readUnicodeString(resourceSectionOffset + nameOffset);
                parseResourceEntry(entryOffset, dataOffset, level + 1, path + "/" + name);
            } else {
                String typeName = level == 0 ? getResourceTypeName(nameId) : "ID: " + nameId;
                parseResourceEntry(entryOffset, dataOffset, level + 1, path + "/" + typeName);
            }
            entryOffset += 8;
        }
    }

    private void parseResourceEntry(int entryOffset, int dataOffset, int level, String path) {
        if ((dataOffset & 0x80000000) != 0) {
            int subdirOffset = dataOffset & 0x7FFFFFFF;
            parseResourceDirectory(resourceSectionOffset + subdirOffset, level + 1, path);
        } else {
            int dataEntryOffset = resourceSectionOffset + dataOffset;
            if (dataEntryOffset < 0 || dataEntryOffset + 16 >= fileBytes.length) {
                System.err.println("Invalid data entry offset: 0x" + Integer.toHexString(dataEntryOffset));
                return;
            }

            ResourceEntry entry = new ResourceEntry();
            entry.rva = readDword(dataEntryOffset);
            entry.size = readDword(dataEntryOffset + 4);
            entry.fileOffset = findSectionOffset(entry.rva);

            // Parse path to extract type and IDs
            String[] parts = path.split("/");
            if (parts.length >= 2) {
                entry.type = parts[1].startsWith("RT_") ? parts[1] : getResourceTypeName(Integer.parseInt(parts[1].replace("ID: ", "")));
                if (parts.length >= 3) {
                    entry.id1 = parts[2].startsWith("ID: ") ? parts[2].substring(4) : parts[2];
                }
                if (parts.length >= 4) {
                    entry.id2 = parts[3].startsWith("ID: ") ? parts[3].substring(4) : parts[3];
                }
            }

            analyzeResourceContent(entry);
            resources.add(entry);
        }
    }

    private void analyzeResourceContent(ResourceEntry entry) {
        if (entry.fileOffset == -1 || entry.size <= 0 || entry.fileOffset + 8 >= fileBytes.length) {
            entry.details = "";
            return;
        }

        byte[] header = new byte[Math.min(8, entry.size)];
        System.arraycopy(fileBytes, entry.fileOffset, header, 0, header.length);

        if (entry.type.equals("RT_ICON") || entry.type.equals("RT_GROUP_ICON")) {
            if (header.length >= 8 && header[0] == (byte)0x89 && "PNG".equals(new String(header, 1, 3))) {
                entry.details = "PNG image";
            } else {
                entry.details = "Windows icon";
            }
        }
        else if (entry.type.equals("RT_RCDATA")) {
            if (header.length >= 8 && header[0] == (byte)0x89 && "PNG".equals(new String(header, 1, 3))) {
                entry.details = "PNG image";
            } else {
                entry.details = "";
            }
        }
        else if (entry.type.equals("RT_MANIFEST")) {
            entry.details = "Windows Visual Stylesheet";
        }
        else if (entry.type.equals("RT_VERSION")) {
            entry.details = "";
        }
        else if (entry.type.equals("RT_DIALOG")) {
            entry.details = "";
        }
        else {
            entry.details = "";
        }
    }

    private String getResourceTypeName(int typeId) {
        return RESOURCE_TYPES.getOrDefault(typeId, "UNKNOWN_" + typeId);
    }

    private int readDword(int offset) {
        if (offset < 0 || offset + 4 > fileBytes.length) {
            System.err.println("Invalid DWORD read at offset: 0x" + Integer.toHexString(offset));
            return 0;
        }
        return ByteBuffer.wrap(fileBytes, offset, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private int readWord(int offset) {
        if (offset < 0 || offset + 2 > fileBytes.length) {
            System.err.println("Invalid WORD read at offset: 0x" + Integer.toHexString(offset));
            return 0;
        }
        return ByteBuffer.wrap(fileBytes, offset, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
    }

    private String readUnicodeString(int offset) {
        if (offset < 0 || offset + 2 > fileBytes.length) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        while (offset + 1 < fileBytes.length) {
            char c = (char) ByteBuffer.wrap(fileBytes, offset, 2)
                    .order(ByteOrder.LITTLE_ENDIAN).getShort();
            if (c == 0) break;
            sb.append(c);
            offset += 2;
        }
        return sb.toString();
    }

    public void printResourceAnalysis() {
        System.out.println("Resource Analysis");
        System.out.println("================================================");

        for (ResourceEntry entry : resources) {
            System.out.printf("%-12s\tID: %s\tID: %s\t%-8d%-8d\t%s\n",
                    entry.type,
                    entry.id1 != null ? entry.id1 : "0",
                    entry.id2 != null ? entry.id2 : "0",
                    entry.fileOffset,
                    entry.size,
                    entry.details != null ? entry.details : "");
        }
    }

    public List<ResourceEntry> getResources() {
        return resources;
    }

    public static class ResourceEntry {
        public String type;
        public String id1;
        public String id2;
        public int rva;
        public int fileOffset;
        public int size;
        public String details;
    }

    public static void main(String[] args) {
        try {
            if (args.length < 1) {
                System.out.println("Usage: java PEResourceAnalyzer <pefile>");
                return;
            }

            byte[] fileBytes = Files.readAllBytes(Paths.get(args[0]));
            PEResourceAnalyzer analyzer = new PEResourceAnalyzer(fileBytes);
            analyzer.printResourceAnalysis();

        } catch (Exception e) {
            System.err.println("Error analyzing file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}