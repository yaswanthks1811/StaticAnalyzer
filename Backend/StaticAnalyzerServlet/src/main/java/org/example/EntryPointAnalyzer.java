package org.example;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class EntryPointAnalyzer implements Serializable {
    private final byte[] fileBytes;
    private final List<String> instructions = new ArrayList<>();
    private int entryPointOffset;
    private int entryPointRva;

    public EntryPointAnalyzer(byte[] fileBytes) {
        this.fileBytes = fileBytes;
        parsePEHeader();
        extractInstructions();
    }

    private void parsePEHeader() {
        // Check MZ header
        // System.out.println(fileBytes[0]+" "+fileBytes[1]);
        if (fileBytes[0] != 0x4D && fileBytes[1] != 0x5A) { // MZ header
            throw new IllegalArgumentException("Not a valid PE file");
        }

        // Get PE header offset
        int peOffset = ByteBuffer.wrap(fileBytes, 0x3C, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        // Get entry point RVA
        this.entryPointRva = ByteBuffer.wrap(fileBytes, peOffset + 0x28, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        // Convert RVA to file offset (simplified)
        this.entryPointOffset = entryPointRva; // Should properly map sections
    }

    private void extractInstructions() {
        int offset = entryPointOffset;
        int maxOffset = Math.min(offset + 200, fileBytes.length); // Limit to first 200 bytes

        while (offset < maxOffset) {
            // Simplified disassembly - real implementation would use a proper disassembler
            String instruction = disassembleInstruction(offset);
            instructions.add(String.format("0x%08X: %s", entryPointRva + (offset - entryPointOffset), instruction));
            offset += getInstructionSize(offset);
        }
    }

    private String disassembleInstruction(int offset) {
        // Very basic disassembly for demonstration
        // A real implementation would use a proper x86 disassembler library

        byte opcode = fileBytes[offset];

        // Handle some common instructions
        switch (opcode & 0xFF) {
            case 0x83:
                return "sub esp, " + readImmediate(offset + 2, 1);
            case 0x53:
                return "push ebx";
            case 0x55:
                return "push ebp";
            case 0x56:
                return "push esi";
            case 0x33:
                return (fileBytes[offset + 1] == 0xDB) ? "xor ebx, ebx" : "xor ???";
            case 0x57:
                return "push edi";
            // case 0x89: return handleMovInstruction(offset);
            // case 0xC6: return handleByteMov(offset);
            // case 0xFF: return handleCallIndirect(offset);
            case 0xE8:
                return "call " + readRelativeCallTarget(offset);
            // Add more opcodes as needed
            default:
                return String.format("db 0x%02X", opcode);
        }
    }

    private String handleMovInstruction(int offset) {
        byte modRM = fileBytes[offset + 1];
        // Very simplified - just handle some patterns we see in the sample
        if (modRM == 0x5C && fileBytes[offset + 2] == 0x24) {
            int disp = fileBytes[offset + 3];
            return String.format("mov [esp+%02xh], ebx", disp);
        }
        return "mov ???";
    }

    private String readImmediate(int offset, int size) {
        int value = 0;
        for (int i = 0; i < size; i++) {
            value |= (fileBytes[offset + i] & 0xFF) << (i * 8);
        }
        return String.format("%08Xh", value);
    }

    private String readRelativeCallTarget(int offset) {
        int rel = ByteBuffer.wrap(fileBytes, offset + 1, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
        int target = (offset + 5 + rel) - entryPointOffset + entryPointRva;
        return String.format("%08Xh", target);
    }

    private int getInstructionSize(int offset) {
        // Very simplified - real implementation would properly decode instructions
        byte opcode = fileBytes[offset];
        switch (opcode & 0xFF) {
            case 0x83:
                return 3; // sub esp, imm8
            case 0x53:
            case 0x55:
            case 0x56:
            case 0x57:
                return 1;
            case 0x33:
                return 2;
            case 0x89:
                return 4; // mov [esp+disp8], reg
            case 0xC6:
                return 4; // mov byte ptr [esp+disp8], imm8
            case 0xFF:
                return 6; // call dword ptr [addr]
            case 0xE8:
                return 5; // call rel32
            default:
                return 1;
        }
    }

    public List<String> getInstructions() {
        return instructions;
    }

    public void printInstructions() {
        System.out.println("Entry Point Instructions (RVA: 0x" +
                Integer.toHexString(entryPointRva) + ")");
        System.out.println("----------------------------------------");
        for (String inst : instructions) {
            System.out.println(inst);
        }
    }

    public static void main(String[] args) {
        try {
            byte[] fileBytes = Files.readAllBytes(Paths.get("NingBoBankBuddy.exe"));
            EntryPointAnalyzer analyzer = new EntryPointAnalyzer(fileBytes);
            analyzer.printInstructions();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}