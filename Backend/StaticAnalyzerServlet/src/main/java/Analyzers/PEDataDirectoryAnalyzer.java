package Analyzers;

import Bean.DataDirectory;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class PEDataDirectoryAnalyzer implements Serializable {

    private static final String[] DIRECTORY_NAMES = {
            "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION",
            "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE",
            "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
            "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"
    };

    private final byte[] fileBytes;
    private final List<DataDirectory> directories = new ArrayList<>();

    public PEDataDirectoryAnalyzer(byte[] fileBytes) {
        this.fileBytes = fileBytes;
        parseDataDirectories();
    }

    private void parseDataDirectories() {
        // 1. Get PE header offset
        int peOffset = ByteBuffer.wrap(fileBytes, 0x3C, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        // 2. Check if PE is 32-bit (0x10B) or 64-bit (0x20B)
        int optionalHeaderMagic = ByteBuffer.wrap(fileBytes, peOffset + 24, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        boolean is64Bit = (optionalHeaderMagic == 0x20B);

        // 3. Calculate data directory offset (32-bit: +96, 64-bit: +112)
        int dataDirOffset = peOffset + 24 + (is64Bit ? 112 : 96);

        // 4. Parse all 16 directories with validation
        for (int i = 0; i < 16; i++) {
            int va = ByteBuffer.wrap(fileBytes, dataDirOffset + (i * 8), 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();
            int size = ByteBuffer.wrap(fileBytes, dataDirOffset + (i * 8) + 4, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();

            // Skip empty directories (except SECURITY/Certificate Table, which can have VA=0)
            if (va == 0 && size == 0 && i != 4) {
                continue;
            }

            // Find containing section (or "N/A" if invalid)
            String section = findContainingSection(va, size);

            // Add directory (with index-based name)
            directories.add(new DataDirectory(i, DIRECTORY_NAMES[i], va, size, section));

            // Critical directory checks
            if (i == 1 && size == 0) { // IMPORT directory is usually required
                System.err.println("Warning: Import Table is empty or missing!");
            }
        }
    }

    private String findContainingSection(int va, int size) {
        if (va == 0 || size == 0) return "N/A";

        int peOffset = ByteBuffer.wrap(fileBytes, 0x3C, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        // Get section headers
        int numberOfSections = ByteBuffer.wrap(fileBytes, peOffset + 6, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        int sizeOfOptionalHeader = ByteBuffer.wrap(fileBytes, peOffset + 20, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        int sectionOffset = peOffset + 24 + sizeOfOptionalHeader;

        for (int i = 0; i < numberOfSections; i++) {
            if (sectionOffset + 40 > fileBytes.length) break;

            // Read section header
            int sectionVa = ByteBuffer.wrap(fileBytes, sectionOffset + 12, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();
            int sectionSize = ByteBuffer.wrap(fileBytes, sectionOffset + 8, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();

            // Extract section name (up to 8 bytes, null-terminated)
            StringBuilder name = new StringBuilder();
            for (int j = 0; j < 8; j++) {
                byte b = fileBytes[sectionOffset + j];
                if (b == 0) break;
                if (b >= 32 && b <= 126) name.append((char) b);
            }
            String sectionName = name.toString().trim();
            if (sectionName.isEmpty()) sectionName = "section_" + i;

            // Check if VA falls within this section
            if (va >= sectionVa && va < sectionVa + sectionSize) {
                return sectionName;
            }

            sectionOffset += 40; // Move to next section header
        }

        return "N/A"; // Not found
    }

    public void printDataDirectories() {
        System.out.println("PE Data Directories");
        System.out.println("----------------------------------------");
        System.out.printf("%-4s %-20s %-10s %-10s %-10s%n",
                "#", "Name", "VA", "Size", "Section");

        for (DataDirectory dir : directories) {
            System.out.printf("%-4d %-20s 0x%-8X 0x%-8X %-10s%n",
                    dir.getIndex(), dir.getName(), dir.getVirtualAddress(), dir.getSize(), dir.getSection());
        }
    }

    public List<DataDirectory> getDirectories() {
        return directories;
    }


}