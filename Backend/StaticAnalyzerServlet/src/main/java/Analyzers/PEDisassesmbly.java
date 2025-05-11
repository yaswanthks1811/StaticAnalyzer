package Analyzers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class PEDisassesmbly {
    public void disassesmbly(String filePath) throws IOException {
        String command = "objdump -d " + filePath; // Replace with the correct command
        Process process = Runtime.getRuntime().exec(command);
        // Read and display the disassembly output
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            int counter = 0;
            while ((line = reader.readLine()) != null && counter++ <= 15) {
                System.out.println(line);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
