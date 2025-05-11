package org.example;

import Bean.PEStaticInfo;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.zip.CRC32;

public class PEInfoParser {
    private static final Map<Integer, String> DLL_CHARACTERISTICS = new HashMap<>();
    private static final Map<Integer, String> SUBSYSTEMS = new HashMap<>();
    private static final Map<Integer, String> FILE_CHARACTERISTICS = new HashMap<>();

    static {
        // DLL Characteristics
        DLL_CHARACTERISTICS.put(0x0020, "HIGH_ENTROPY_VA");
        DLL_CHARACTERISTICS.put(0x0040, "DYNAMIC_BASE");
        DLL_CHARACTERISTICS.put(0x0100, "NX_COMPAT");
        DLL_CHARACTERISTICS.put(0x0200, "FORCE_INTEGRITY");
        DLL_CHARACTERISTICS.put(0x0400, "NO_SEH");
        DLL_CHARACTERISTICS.put(0x0800, "NO_BIND");
        DLL_CHARACTERISTICS.put(0x1000, "APPCONTAINER");
        DLL_CHARACTERISTICS.put(0x2000, "WDM_DRIVER");
        DLL_CHARACTERISTICS.put(0x4000, "GUARD_CF");
        DLL_CHARACTERISTICS.put(0x8000, "TERMINAL_SERVER_AWARE");

        // Subsystems
        SUBSYSTEMS.put(0, "UNKNOWN");
        SUBSYSTEMS.put(1, "NATIVE");
        SUBSYSTEMS.put(2, "WINDOWS_GUI");
        SUBSYSTEMS.put(3, "WINDOWS_CUI");
        SUBSYSTEMS.put(5, "OS2_CUI");
        SUBSYSTEMS.put(7, "POSIX_CUI");
        SUBSYSTEMS.put(8, "NATIVE_WINDOWS");
        SUBSYSTEMS.put(9, "WINDOWS_CE_GUI");
        SUBSYSTEMS.put(10, "EFI_APPLICATION");
        SUBSYSTEMS.put(11, "EFI_BOOT_SERVICE_DRIVER");
        SUBSYSTEMS.put(12, "EFI_RUNTIME_DRIVER");
        SUBSYSTEMS.put(13, "EFI_ROM");
        SUBSYSTEMS.put(14, "XBOX");

        // File Characteristics
        FILE_CHARACTERISTICS.put(0x0001, "RELOCS_STRIPPED");
        FILE_CHARACTERISTICS.put(0x0002, "EXECUTABLE_IMAGE");
        FILE_CHARACTERISTICS.put(0x0004, "LINE_NUMS_STRIPPED");
        FILE_CHARACTERISTICS.put(0x0008, "LOCAL_SYMS_STRIPPED");
        FILE_CHARACTERISTICS.put(0x0010, "AGGRESSIVE_WS_TRIM");
        FILE_CHARACTERISTICS.put(0x0020, "LARGE_ADDRESS_AWARE");
        FILE_CHARACTERISTICS.put(0x0040, "BYTES_REVERSED_LO");
        FILE_CHARACTERISTICS.put(0x0080, "32BIT_MACHINE");
        FILE_CHARACTERISTICS.put(0x0100, "DEBUG_STRIPPED");
        FILE_CHARACTERISTICS.put(0x0200, "REMOVABLE_RUN_FROM_SWAP");
        FILE_CHARACTERISTICS.put(0x0400, "NET_RUN_FROM_SWAP");
        FILE_CHARACTERISTICS.put(0x0800, "SYSTEM");
        FILE_CHARACTERISTICS.put(0x1000, "DLL");
        FILE_CHARACTERISTICS.put(0x2000, "UP_SYSTEM_ONLY");
        FILE_CHARACTERISTICS.put(0x4000, "BYTES_REVERSED_HI");
    }

    public PEStaticInfo getPEInfo(byte[] fileBytes) {
        return analyzePE(fileBytes);
    }

    private PEStaticInfo analyzePE(byte[] fileBytes) {
        PEStaticInfo info = new PEStaticInfo();

        // Check MZ header
        if (fileBytes.length < 2 || fileBytes[0] != 'M' || fileBytes[1] != 'Z') {
            throw new IllegalArgumentException("Not a valid PE file (missing MZ header)");
        }

        int peHeaderOffset = readDword(fileBytes, 0x3C);
        if (peHeaderOffset <= 0 || peHeaderOffset + 248 >= fileBytes.length) {
            throw new IllegalArgumentException("Invalid PE header offset");
        }

        // Check PE signature
        if (readDword(fileBytes, peHeaderOffset) != 0x00004550) {  // "PE\0\0"
            throw new IllegalArgumentException("Invalid PE signature");
        }

        // COFF Header
        int timeDateStamp = readDword(fileBytes, peHeaderOffset + 8);
        int characteristics = readWord(fileBytes, peHeaderOffset + 22);

        // Optional Header
        int optionalHeaderOffset = peHeaderOffset + 24;
        int magic = readWord(fileBytes, optionalHeaderOffset);

        // Validate magic number
        if (magic != 0x10B && magic != 0x20B) {
            throw new IllegalArgumentException("Invalid optional header magic number: 0x" +
                    Integer.toHexString(magic).toUpperCase());
        }

        boolean is64bit = (magic == 0x20B);

        // Set basic info
        info.setEntryPoint(readDword(fileBytes, optionalHeaderOffset + 16));
        info.setEntryPointSection(findSectionByRva(fileBytes, peHeaderOffset, (int) info.getEntryPoint()));
        info.setImageBase(is64bit ? readQword(fileBytes, optionalHeaderOffset + 24)
                : readDword(fileBytes, optionalHeaderOffset + 24));
        info.setDigitallySigned(readDword(fileBytes, optionalHeaderOffset + (is64bit ? 144 : 128)) != 0);

        // Set versions
        info.setOsVersionMajor(readWord(fileBytes, optionalHeaderOffset + (is64bit ? 40 : 36)));
        info.setOsVersionMinor(readWord(fileBytes, optionalHeaderOffset + (is64bit ? 42 : 38)));
        info.setFileVersionMajor(readWord(fileBytes, optionalHeaderOffset + (is64bit ? 44 : 40)));
        info.setFileVersionMinor(readWord(fileBytes, optionalHeaderOffset + (is64bit ? 46 : 42)));
        info.setSubsystemVersionMajor(readWord(fileBytes, optionalHeaderOffset + (is64bit ? 48 : 44)));
        info.setSubsystemVersionMinor(readWord(fileBytes, optionalHeaderOffset + (is64bit ? 50 : 46)));

        // Set characteristics
        int subsystemValue = readWord(fileBytes, optionalHeaderOffset + (is64bit ? 68 : 64));
        info.setSubsystem(SUBSYSTEMS.getOrDefault(subsystemValue, "UNKNOWN (0x" + Integer.toHexString(subsystemValue) + ")"));
        info.setImageFileCharacteristics(getCharacteristics(FILE_CHARACTERISTICS, characteristics));
        info.setDllCharacteristics(getCharacteristics(DLL_CHARACTERISTICS,
                readWord(fileBytes, optionalHeaderOffset + (is64bit ? 70 : 66))));

        // Set timestamp with formatted date
        SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss yyyy z");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        String formattedDate = sdf.format(new Date((long) timeDateStamp * 1000));
        info.setTimeStamp(String.format("0x%X [%s]", timeDateStamp, formattedDate));

        // Set other fields
        info.setTlsCallbacks(
                readDword(fileBytes, optionalHeaderOffset + (is64bit ? 184 : 168)) != 0 ? "Present" : "None");
        info.setClrVersion(
                readDword(fileBytes, optionalHeaderOffset + (is64bit ? 224 : 208)) != 0 ? "Present" : "None");
        info.setImportHash(calculateImportHash(fileBytes, peHeaderOffset, optionalHeaderOffset, is64bit));

        return info;
    }

    private String findSectionByRva(byte[] fileBytes, int peHeaderOffset, int rva) {
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

            if (rva >= virtualAddress && rva < virtualAddress + virtualSize) {
                StringBuilder name = new StringBuilder();
                for (int j = 0; j < 8; j++) {
                    byte b = fileBytes[sectionOffset + j];
                    if (b == 0)
                        break;
                    name.append((char) b);
                }
                return name.toString().trim();
            }
        }
        return "UNKNOWN";
    }

    private String getCharacteristics(Map<Integer, String> map, int value) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Integer, String> entry : map.entrySet()) {
            if ((value & entry.getKey()) != 0) {
                if (sb.length() > 0)
                    sb.append(", ");
                sb.append(entry.getValue());
            }
        }
        return sb.toString();
    }

    private String calculateImportHash(byte[] fileBytes, int peHeaderOffset, int optionalHeaderOffset,
            boolean is64bit) {
        int importTableRva = readDword(fileBytes, optionalHeaderOffset + (is64bit ? 120 : 104));
        int importTableSize = readDword(fileBytes, optionalHeaderOffset + (is64bit ? 124 : 108));

        if (importTableRva == 0 || importTableSize == 0) {
            return "";
        }

        int importTableOffset = rvaToOffset(fileBytes, peHeaderOffset, importTableRva);
        if (importTableOffset == -1) {
            return "";
        }

        CRC32 crc = new CRC32();
        int offset = importTableOffset;

        while (true) {
            int nameRva = readDword(fileBytes, offset + 12);
            if (nameRva == 0)
                break;

            int nameOffset = rvaToOffset(fileBytes, peHeaderOffset, nameRva);
            if (nameOffset == -1)
                break;

            // Read DLL name
            int nameLength = 0;
            while (nameOffset + nameLength < fileBytes.length && fileBytes[nameOffset + nameLength] != 0) {
                nameLength++;
            }

            if (nameLength > 0) {
                crc.update(fileBytes, nameOffset, nameLength);
            }

            offset += 20; // Size of IMAGE_IMPORT_DESCRIPTOR
            if (offset + 20 > fileBytes.length)
                break;
        }

        return String.format("%08x", crc.getValue());
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