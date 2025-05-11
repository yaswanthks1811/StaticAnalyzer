package org.example;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class PESectionAnalyzer implements Serializable {

    private final byte[] fileBytes;
    private final List<PESection> sections = new ArrayList<>();

    public PESectionAnalyzer(byte[] fileBytes) {
        this.fileBytes = fileBytes;
        parseSections();
    }

    private void parseSections() {
        // Get PE header offset
        int peOffset = ByteBuffer.wrap(fileBytes, 0x3C, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        // Get number of sections
        int numSections = ByteBuffer.wrap(fileBytes, peOffset + 6, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;

        // Get section headers start (after optional header)
        int optionalHeaderSize = ByteBuffer.wrap(fileBytes, peOffset + 20, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        int sectionOffset = peOffset + 24 + optionalHeaderSize;

        // Parse each section
        for (int i = 0; i < numSections; i++) {
            PESection section = new PESection();

            // Read section name (8 bytes)
            byte[] nameBytes = new byte[8];
            System.arraycopy(fileBytes, sectionOffset, nameBytes, 0, 8);
            section.name = new String(nameBytes).trim();

            // Read section characteristics
            section.virtualSize = ByteBuffer.wrap(fileBytes, sectionOffset + 8, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();
            section.virtualAddress = ByteBuffer.wrap(fileBytes, sectionOffset + 12, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();
            section.rawSize = ByteBuffer.wrap(fileBytes, sectionOffset + 16, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();
            section.rawOffset = ByteBuffer.wrap(fileBytes, sectionOffset + 20, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();
            section.characteristics = ByteBuffer.wrap(fileBytes, sectionOffset + 36, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();

            // Calculate MD5 hash of section content
            section.md5 = calculateSectionMD5(section);

            // Calculate entropy
            section.entropy = calculateEntropy(section);

            // Determine section type
            section.type = determineSectionType(section);

            sections.add(section);
            sectionOffset += 40; // Move to next section header
        }
    }

    private String calculateSectionMD5(PESection section) {
        if (section.rawSize == 0)
            return "d41d8cd98f00b204e9800998ecf8427e"; // Empty MD5

        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            int end = Math.min(section.rawOffset + section.rawSize, fileBytes.length);
            md.update(fileBytes, section.rawOffset, end - section.rawOffset);
            byte[] digest = md.digest();

            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "error";
        }
    }

    private double calculateEntropy(PESection section) {
        if (section.rawSize == 0)
            return 0.0;

        int[] frequency = new int[256];
        int count = 0;
        int end = Math.min(section.rawOffset + section.rawSize, fileBytes.length);

        for (int i = section.rawOffset; i < end; i++) {
            frequency[fileBytes[i] & 0xFF]++;
            count++;
        }

        double entropy = 0.0;
        for (int j = 0; j < 256; j++) {
            if (frequency[j] > 0) {
                double p = (double) frequency[j] / count;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }

        return entropy;
    }

    private String determineSectionType(PESection section) {
        if ((section.characteristics & 0x00000020) != 0) {
            return "code";
        } else if ((section.characteristics & 0x00000040) != 0) {
            return "initialized_data";
        } else if ((section.characteristics & 0x00000080) != 0) {
            return "uninitialized_data";
        } else if (section.name.equals(".rsrc")) {
            return "resources";
        } else if (section.name.equals(".reloc")) {
            return "relocations";
        }
        return "unknown";
    }

    public void printSectionAnalysis() {
        System.out.println("PE Section Analysis");
        System.out.println(
                "===============================================================================================================");
        System.out.printf("%-8s %-10s %-10s %-10s %-34s %-8s %-10s %-10s %s\n",
                "Name", "VirtAddr", "VirtSize", "RawSize", "MD5", "Entropy", "Type", "Exec", "Write");

        for (PESection section : sections) {
            System.out.printf("%-8s 0x%-8X 0x%-8X 0x%-8X %-34s %-8.2f %-10s %-10s %s\n",
                    section.name,
                    section.virtualAddress,
                    section.virtualSize,
                    section.rawSize,
                    section.md5,
                    section.entropy,
                    section.type,
                    isExecutable(section) ? "YES" : "NO",
                    isWritable(section) ? "YES" : "NO");
        }

        printSectionStatistics();
        analyzePotentialPacking();
    }

    private boolean isExecutable(PESection section) {
        return (section.characteristics & 0x20000000) != 0;
    }

    private boolean isWritable(PESection section) {
        return (section.characteristics & 0x80000000) != 0;
    }

    private void printSectionStatistics() {
        System.out.println("\nSection Statistics:");
        System.out.println("----------------------------------------");
        System.out.printf("Total sections: %d\n", sections.size());

        long totalVirtualSize = sections.stream().mapToLong(s -> s.virtualSize).sum();
        long totalRawSize = sections.stream().mapToLong(s -> s.rawSize).sum();
        System.out.printf("Total virtual size: 0x%X\n", totalVirtualSize);
        System.out.printf("Total raw size: 0x%X\n", totalRawSize);

        System.out.println("\nExecutable sections: " +
                sections.stream().filter(this::isExecutable).count());
        System.out.println("Writable sections: " +
                sections.stream().filter(this::isWritable).count());
    }

    private void analyzePotentialPacking() {
        System.out.println("\nPacking Analysis:");
        System.out.println("----------------------------------------");

        // Check for high entropy in executable sections
        sections.stream()
                .filter(s -> isExecutable(s) && s.entropy > 6.5)
                .forEach(s -> System.out.printf(
                        "Warning: High entropy (%.2f) in %s - possible packing/encryption\n",
                        s.entropy, s.name));

        // Check for section name anomalies
        sections.stream()
                .filter(s -> s.name.contains("UPX") || s.name.contains("ASPack"))
                .forEach(s -> System.out.printf(
                        "Warning: Suspicious section name '%s' - possible packed executable\n",
                        s.name));

        // Check for size mismatches
        sections.stream()
                .filter(s -> s.virtualSize > 0 && s.rawSize == 0)
                .forEach(s -> System.out.printf(
                        "Warning: Virtual size (0x%X) but no raw data in %s - possible runtime allocation\n",
                        s.virtualSize, s.name));
    }

    public static class PESection {
        public String name;
        public int virtualSize;
        public int virtualAddress;
        public int rawSize;
        public int rawOffset;
        public int characteristics;
        public String md5;
        public double entropy;
        public String type;
    }

    public List<PESection> getSections() {
        return sections;
    }

    public static void main(String[] args) {
        try {
            byte[] fileBytes = Files.readAllBytes(Paths.get("NingBoBankBuddy.exe"));
            PESectionAnalyzer analyzer = new PESectionAnalyzer(fileBytes);
            analyzer.printSectionAnalysis();

            // Example: Check for suspicious sections
            PESection textSection = analyzer.getSections().stream()
                    .filter(s -> s.name.equals(".text"))
                    .findFirst().orElse(null);
            if (textSection != null && textSection.entropy > 6.5) {
                System.out.println("\nSecurity Warning: .text section has high entropy - possible packed code");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}