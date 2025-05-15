package Analyzers;

import Bean.PEStaticInfo;
import Utilities.Utils;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

public class PEInfoParser {
    private static final Map<Integer, String> DLL_CHARACTERISTICS =
            new HashMap<>();
    private static final Map<Integer, String> SUBSYSTEMS = new HashMap<>();
    private static final Map<Integer, String> FILE_CHARACTERISTICS =
            new HashMap<>();

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
        if (fileBytes.length < 2 || fileBytes[0] != 'M' ||
                fileBytes[1] != 'Z') {
            throw new IllegalArgumentException("Not a valid PE file (missing MZ header)");
        }

        int peHeaderOffset = Utils.readDWord(fileBytes, 0x3C);
        if (peHeaderOffset <= 0 || peHeaderOffset + 248 >= fileBytes.length) {
            throw new IllegalArgumentException("Invalid PE header offset");
        }

        // Check PE signature
        if (Utils.readDWord(fileBytes, peHeaderOffset) != 0x00004550) {  // "PE\0\0"
            throw new IllegalArgumentException("Invalid PE signature");
        }

        // COFF Header
        int timeDateStamp = Utils.readDWord(fileBytes, peHeaderOffset + 8);
        int characteristics = Utils.readWord(fileBytes, peHeaderOffset + 22);

        // Optional Header
        int optionalHeaderOffset = peHeaderOffset + 24;
        int magic = Utils.readWord(fileBytes, optionalHeaderOffset);

        // Validate magic number
        if (magic != 0x10B && magic != 0x20B) {
            throw new IllegalArgumentException("Invalid optional header magic number: 0x" +
                    Integer.toHexString(magic).toUpperCase());
        }

        boolean is64bit = (magic == 0x20B);

        // Set basic info
        info.setEntryPoint(Utils.readDWord(fileBytes, optionalHeaderOffset + 16));
        info.setEntryPointSection(findSectionByRva(fileBytes,
                peHeaderOffset, (int) info.getEntryPoint()));
        info.setImageBase(is64bit ? Utils.readQWord(fileBytes,
                optionalHeaderOffset + 24)
                : Utils.readDWord(fileBytes, optionalHeaderOffset + 24));
        info.setDigitallySigned(Utils.readDWord(fileBytes,
                optionalHeaderOffset + (is64bit ? 144 : 128)) != 0);

        // Set versions
        //PE32 has extra row baseOfData(so adding 4 to all the PE32 files)
        info.setOsVersionMajor(Utils.readWord(fileBytes,
                optionalHeaderOffset + 40));
        info.setOsVersionMinor(Utils.readWord(fileBytes,
                optionalHeaderOffset + 42));
        info.setFileVersionMajor(Utils.readWord(fileBytes,
                optionalHeaderOffset + 44));
        info.setFileVersionMinor(Utils.readWord(fileBytes,
                optionalHeaderOffset + 46));
        info.setSubsystemVersionMajor(Utils.readWord(fileBytes,
                optionalHeaderOffset + 48));
        info.setSubsystemVersionMinor(Utils.readWord(fileBytes,
                optionalHeaderOffset + 50));

        // Set characteristics
        int subsystemValue = Utils.readWord(fileBytes, optionalHeaderOffset
                + 68);
        info.setSubsystem(SUBSYSTEMS.getOrDefault(subsystemValue,
                "UNKNOWN (0x" + Integer.toHexString(subsystemValue) + ")"));
        info.setImageFileCharacteristics(getCharacteristics(FILE_CHARACTERISTICS,
                characteristics));
        info.setDllCharacteristics(getCharacteristics(DLL_CHARACTERISTICS,
                Utils.readWord(fileBytes, optionalHeaderOffset + 70)));
        System.out.println(optionalHeaderOffset+70);

        // Set timestamp with formatted date
        SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss yyyy z");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        String formattedDate = sdf.format(new Date((long)
                timeDateStamp * 1000));
        info.setTimeStamp(String.format("0x%X [%s]", timeDateStamp,
                formattedDate));

        // Set other fields
        info.setTlsCallbacks(
                Utils.readDWord(fileBytes, optionalHeaderOffset + (is64bit ?
                        184 : 172)) != 0 ? "Present" : "None");
        info.setClrVersion(
                Utils.readDWord(fileBytes, optionalHeaderOffset + (is64bit ?
                        224 : 212)) != 0 ? "Present" : "None");
        int richOffset = findRichHeaderOffset(fileBytes,peHeaderOffset);
        info.setRichHeaderOffset(richOffset);

        info.setXorkey(decodeRichHeader(fileBytes, richOffset));
        info.setImportHash(calculateImportHash(fileBytes,
                peHeaderOffset, optionalHeaderOffset, is64bit));

        return info;
    }

    private String findSectionByRva(byte[] fileBytes, int
            peHeaderOffset, int rva) {
        int numberOfSections = Utils.readWord(fileBytes, peHeaderOffset + 6);
        int sizeOfOptionalHeader = Utils.readWord(fileBytes, peHeaderOffset + 20);
        int sectionTableOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;

        for (int i = 0; i < numberOfSections; i++) {
            int sectionOffset = sectionTableOffset + (i * 40);
            if (sectionOffset + 40 > fileBytes.length)
                break;

            int virtualAddress = Utils.readDWord(fileBytes, sectionOffset + 12);
            int virtualSize = Utils.readDWord(fileBytes, sectionOffset + 8);
            int pointerToRawData = Utils.readDWord(fileBytes, sectionOffset + 20);

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

    private String calculateImportHash(byte[] fileBytes, int
                                               peHeaderOffset, int optionalHeaderOffset,
                                       boolean is64bit) {
        int importTableRva = Utils.readDWord(fileBytes, optionalHeaderOffset
                + (is64bit ? 120 : 104));
        int importTableSize = Utils.readDWord(fileBytes,
                optionalHeaderOffset + (is64bit ? 124 : 108));

        if (importTableRva == 0 || importTableSize == 0) {
            return "";
        }

        int importTableOffset = rvaToOffset(fileBytes, peHeaderOffset,
                importTableRva);
        if (importTableOffset == -1) {
            return "";
        }

        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            int offset = importTableOffset;

            while (true) {
                int nameRva = Utils.readDWord(fileBytes, offset + 12);
                if (nameRva == 0) break;

                int nameOffset = rvaToOffset(fileBytes, peHeaderOffset, nameRva);
                if (nameOffset == -1) break;

                // Read DLL name
                int nameLength = 0;
                while (nameOffset + nameLength < fileBytes.length &&
                        fileBytes[nameOffset + nameLength] != 0) {
                    nameLength++;
                }

                if (nameLength > 0) {
                    md.update(fileBytes, nameOffset, nameLength);
                }

                offset += 20;
                if (offset + 20 > fileBytes.length) break;
            }

            // Convert MD5 bytes to hex string
            byte[] md5Bytes = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : md5Bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "";
        }
    }

    private int rvaToOffset(byte[] fileBytes, int peHeaderOffset, int rva) {
        int numberOfSections = Utils.readWord(fileBytes, peHeaderOffset + 6);
        int sizeOfOptionalHeader = Utils.readWord(fileBytes, peHeaderOffset + 20);
        int sectionTableOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;

        for (int i = 0; i < numberOfSections; i++) {
            int sectionOffset = sectionTableOffset + (i * 40);
            if (sectionOffset + 40 > fileBytes.length)
                break;

            int virtualAddress = Utils.readDWord(fileBytes, sectionOffset + 12);
            int virtualSize = Utils.readDWord(fileBytes, sectionOffset + 8);
            int pointerToRawData = Utils.readDWord(fileBytes, sectionOffset + 20);
            int sizeOfRawData = Utils.readDWord(fileBytes, sectionOffset + 16);

            if (rva >= virtualAddress && rva < virtualAddress + virtualSize) {
                if (sizeOfRawData == 0) {
                    return rva;
                }
                return pointerToRawData + (rva - virtualAddress);
            }
        }
        return -1;
    }
    private static int findRichHeaderOffset(byte[] fileBytes, int peHeaderOffset) {
        // Search backwards from PE header for "Rich" (0x68636952)
        final int searchWindow = 256; // Reasonable search range
        int startPos = Math.max(0, peHeaderOffset - searchWindow);

        for (int i = peHeaderOffset - 4; i >= startPos; i--) {
            if (fileBytes[i] == 0x52 && fileBytes[i+1] == 0x69 &&
                    fileBytes[i+2] == 0x63 && fileBytes[i+3] == 0x68) {  // "Rich"
                return i;
            }
        }
        return -1;
    }

    private static String decodeRichHeader(byte[] fileBytes, int richOffset) {
        // Read XOR key (4 bytes after Rich signature and checksum)
        byte[] xorKey = new byte[4];
        System.arraycopy(fileBytes, richOffset + 4, xorKey, 0, 4);

        System.out.printf("Found Rich Header at offset 0x%X\n", richOffset);
        System.out.printf("XOR Key: 0x%02X 0x%02X 0x%02X 0x%02X\n",
                xorKey[0] & 0xFF, xorKey[1] & 0xFF,
                xorKey[2] & 0xFF, xorKey[3] & 0xFF);
        String xorkeyString = String.format("0x%02X 0x%02X 0x%02X 0x%02X",
                xorKey[0] & 0xFF, xorKey[1] & 0xFF,
                xorKey[2] & 0xFF, xorKey[3] & 0xFF);
        // Read and decode Rich Header entries
        int entryOffset = richOffset - 16; // Start of Rich Header data
        if (entryOffset < 0) {
            System.err.println("Invalid Rich Header offset: too close to start of file.");
            return "";
        }


        while (true) {
            if (entryOffset + 8 > fileBytes.length) break;

            // XOR decrypt each byte with the key
            byte[] decrypted = new byte[8];
            for (int i = 0; i < 8; i++) {
                decrypted[i] = (byte)(fileBytes[entryOffset + i] ^ xorKey[i % 4]);
            }

            int id = (decrypted[1] & 0xFF) << 8 | (decrypted[0] & 0xFF);
            int version = (decrypted[3] & 0xFF) << 8 | (decrypted[2] & 0xFF);
            int count = (decrypted[7] & 0xFF) << 24 |
                    (decrypted[6] & 0xFF) << 16 |
                    (decrypted[5] & 0xFF) << 8 |
                    (decrypted[4] & 0xFF);

            if (id == 0 && version == 0 && count == 0) break; // End marker

            System.out.printf("Comp ID: 0x%04X, Version: %d, Count: %d\n",
                    id, version, count);
            entryOffset += 8;
            return xorkeyString;
        }
        return "";
    }

    

}