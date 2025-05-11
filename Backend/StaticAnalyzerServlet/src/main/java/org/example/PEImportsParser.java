package org.example;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PEImportsParser implements Serializable {

    public static class PEImportsInfo {
        private final Map<String, List<String>> imports = new LinkedHashMap<>();

        public void addImport(String dllName, String functionName) {
            imports.computeIfAbsent(dllName, k -> new ArrayList<>()).add(functionName);
        }

        public Map<String, List<String>> getImports() {
            return imports;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Imports\n");
            sb.append(String.format("%-20s\t%s\n", "DLL", "Import"));

            imports.forEach((dll, functions) -> {
                sb.append(String.format("%-20s\t%s\n",
                        dll,
                        String.join(", ", functions)));
            });
            return sb.toString();
        }
    }

    public PEImportsInfo parse(byte[] fileBytes) throws Exception {
        return analyzeImports(fileBytes);
    }

    private PEImportsInfo analyzeImports(byte[] fileBytes) {
        PEImportsInfo importsInfo = new PEImportsInfo();

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

        // Get Import Table RVA and Size
        int importTableRva = readDword(fileBytes, optionalHeaderOffset + (is64bit ? 120 : 104));
        int importTableSize = readDword(fileBytes, optionalHeaderOffset + (is64bit ? 124 : 108));

        if (importTableRva == 0 || importTableSize == 0) {
            return importsInfo; // No imports
        }

        // Convert RVA to file offset
        int importTableOffset = rvaToOffset(fileBytes, peHeaderOffset, importTableRva);
        if (importTableOffset == -1) {
            return importsInfo;
        }

        // Parse each import descriptor
        int descriptorSize = 20; // Size of IMAGE_IMPORT_DESCRIPTOR
        int offset = importTableOffset;

        while (true) {
            // Check if we've reached the null descriptor
            if (offset + descriptorSize > fileBytes.length)
                break;

            int nameRva = readDword(fileBytes, offset + 12); // Name RVA
            int originalFirstThunk = readDword(fileBytes, offset); // OriginalFirstThunk
            int firstThunk = readDword(fileBytes, offset + 16); // FirstThunk

            if (nameRva == 0 && originalFirstThunk == 0 && firstThunk == 0)
                break;

            // Get DLL name
            int nameOffset = rvaToOffset(fileBytes, peHeaderOffset, nameRva);
            if (nameOffset == -1) {
                offset += descriptorSize;
                continue;
            }

            String dllName = readNullTerminatedString(fileBytes, nameOffset);
            if (dllName.isEmpty()) {
                offset += descriptorSize;
                continue;
            }

            // Get the import address table (use OriginalFirstThunk if available, otherwise
            // FirstThunk)
            int thunkRva = (originalFirstThunk != 0) ? originalFirstThunk : firstThunk;
            int thunkOffset = rvaToOffset(fileBytes, peHeaderOffset, thunkRva);
            if (thunkOffset == -1) {
                offset += descriptorSize;
                continue;
            }

            // Parse each thunk entry
            int thunkEntrySize = is64bit ? 8 : 4;
            int thunkEntryOffset = thunkOffset;

            while (true) {
                if (thunkEntryOffset + thunkEntrySize > fileBytes.length)
                    break;

                long thunkValue = is64bit ? readQword(fileBytes, thunkEntryOffset)
                        : readDword(fileBytes, thunkEntryOffset);
                if (thunkValue == 0)
                    break; // End of list

                // Check if it's an ordinal import (high bit set)
                if ((thunkValue & (is64bit ? 1L << 63 : 1L << 31)) != 0) {
                    // Ordinal import
                    long ordinal = thunkValue & (is64bit ? 0x7FFFFFFFFFFFFFFFL : 0x7FFFFFFF);
                    importsInfo.addImport(dllName, String.format("ordinal_%d", ordinal));
                } else {
                    // Named import
                    int hintNameRva = (int) (thunkValue & 0xFFFFFFFFL);
                    int hintNameOffset = rvaToOffset(fileBytes, peHeaderOffset, hintNameRva);
                    if (hintNameOffset != -1) {
                        int hint = readWord(fileBytes, hintNameOffset);
                        String functionName = readNullTerminatedString(fileBytes, hintNameOffset + 2);
                        importsInfo.addImport(dllName, functionName);
                    }
                }

                thunkEntryOffset += thunkEntrySize;
            }

            offset += descriptorSize;
        }

        return importsInfo;
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

    private static long readQword(byte[] bytes, int offset) {
        if (offset < 0 || offset + 8 > bytes.length)
            return 0;
        return ByteBuffer.wrap(bytes, offset, 8)
                .order(ByteOrder.LITTLE_ENDIAN).getLong();
    }


}