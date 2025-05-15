package Analyzers;

import Utilities.Utils;
import jdk.jshell.execution.Util;

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

        // Get Import Table RVA and Size
        int importTableRva = Utils.readDWord(fileBytes, optionalHeaderOffset + (is64bit ? 120 : 104));
        int importTableSize = Utils.readDWord(fileBytes, optionalHeaderOffset + (is64bit ? 124 : 108));

        if (importTableRva == 0 || importTableSize == 0) {
            return importsInfo; // No imports
        }

        // Convert RVA to file offset
        int importTableOffset = Utils.rvaToOffset(fileBytes, peHeaderOffset, importTableRva);
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

            int nameRva = Utils.readDWord(fileBytes, offset + 12); // Name RVA
            int originalFirstThunk = Utils.readDWord(fileBytes, offset); // OriginalFirstThunk
            int firstThunk = Utils.readDWord(fileBytes, offset + 16); // FirstThunk

            if (nameRva == 0 && originalFirstThunk == 0 && firstThunk == 0)
                break;

            // Get DLL name
            int nameOffset = Utils.rvaToOffset(fileBytes, peHeaderOffset, nameRva);
            if (nameOffset == -1) {
                offset += descriptorSize;
                continue;
            }

            String dllName = Utils.readNullTerminatedString(fileBytes, nameOffset);
            if (dllName.isEmpty()) {
                offset += descriptorSize;
                continue;
            }

            // Get the import address table (use OriginalFirstThunk if available, otherwise
            // FirstThunk)
            int thunkRva = (originalFirstThunk != 0) ? originalFirstThunk : firstThunk;
            int thunkOffset = Utils.rvaToOffset(fileBytes, peHeaderOffset, thunkRva);
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

                long thunkValue = is64bit ? Utils.readQWord(fileBytes, thunkEntryOffset)
                        : Utils.readDWord(fileBytes, thunkEntryOffset);
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
                    int hintNameOffset = Utils.rvaToOffset(fileBytes, peHeaderOffset, hintNameRva);
                    if (hintNameOffset != -1) {
                        int hint = Utils.readWord(fileBytes, hintNameOffset);
                        String functionName = Utils.readNullTerminatedString(fileBytes, hintNameOffset + 2);
                        importsInfo.addImport(dllName, functionName);
                    }
                }

                thunkEntryOffset += thunkEntrySize;
            }

            offset += descriptorSize;
        }

        return importsInfo;
    }


}