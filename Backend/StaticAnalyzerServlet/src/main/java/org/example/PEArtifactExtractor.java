package org.example;

import Bean.PEArtifacts;

import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PEArtifactExtractor implements Serializable {

    private final byte[] fileBytes;
    private final String fileContent;
    private final Set<String> urls = new LinkedHashSet<>();
    private final Set<String> filePaths = new LinkedHashSet<>();
    private final Set<String> ipAddresses = new LinkedHashSet<>();
    private final Set<String> emailAddresses = new LinkedHashSet<>();
    private final Set<String> interestingStrings = new LinkedHashSet<>();

    PEArtifacts artifacts = new PEArtifacts();

    // Regex patterns for artifact detection
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]");
    private static final Pattern FILE_PATTERN = Pattern.compile(
            "[a-zA-Z]:\\\\[^\\\\]+\\\\(?:[^\\\\]+\\\\)*[^\\\\]+|" + // Windows paths
                    "/[^/]+/(?:[^/]+/)*[^/]+|" + // Unix paths
                    "[a-zA-Z0-9_-]+\\.[a-zA-Z0-9]{1,10}" // Filenames
    );
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}");

    public PEArtifactExtractor(byte[] fileBytes) throws IOException {
        this.fileBytes = fileBytes;
        this.fileContent = extractStrings();
        analyzeArtifacts();
    }

    public Set<String> getUrls() {
        return urls;
    }

    public Set<String> getFilePaths() {
        return filePaths;
    }

    public Set<String> getIpAddresses() {
        return ipAddresses;
    }

    public Set<String> getEmailAddresses() {
        return emailAddresses;
    }

    public Set<String> getInterestingStrings() {
        return interestingStrings;
    }

    private String extractStrings() {
        StringBuilder sb = new StringBuilder();
        StringBuilder currentString = new StringBuilder();

        for (byte b : fileBytes) {
            if (b >= 32 && b <= 126) { // Printable ASCII
                currentString.append((char) b);
            } else {
                if (currentString.length() >= 4) { // Minimum string length
                    sb.append(currentString.toString()).append("\n");
                }
                currentString.setLength(0);
            }
        }

        // Add any remaining string
        if (currentString.length() >= 4) {
            sb.append(currentString.toString());
        }

        return sb.toString();
    }

    private void analyzeArtifacts() {
        extractUrls();
        extractFilePaths();
        extractIpAddresses();
        extractEmailAddresses();
        findInterestingStrings();
    }

    private void extractUrls() {
        Matcher matcher = URL_PATTERN.matcher(fileContent);
        while (matcher.find()) {
            String url = matcher.group();
            if (!url.contains("example.com") && url.length() > 10) { // Can add any url to check if that specific url is
                                                                     // present
                urls.add(url);
            }
        }
    }

    private void extractFilePaths() {
        Matcher matcher = FILE_PATTERN.matcher(fileContent);
        while (matcher.find()) {
            String filePath = matcher.group();
            if (!filePath.matches("(?i).*\\.(dll|exe|sys)$") &&
                    !filePath.contains("Windows") &&
                    !filePath.contains("Microsoft")) {
                filePaths.add(filePath);
            }
        }
    }

    private void extractIpAddresses() {
        Matcher matcher = IP_PATTERN.matcher(fileContent);
        while (matcher.find()) {
            String ip = matcher.group();
            if (!ip.startsWith("0.") &&
                    !ip.startsWith("127.") &&
                    !ip.startsWith("255.") &&
                    !ip.equals("0.0.0.0")) {
                ipAddresses.add(ip);
            }
        }
    }

    private void extractEmailAddresses() {
        Matcher matcher = EMAIL_PATTERN.matcher(fileContent);
        while (matcher.find()) {
            String email = matcher.group();
            if (!email.endsWith("@example.com") &&
                    !email.contains("admin@")) {
                emailAddresses.add(email);
            }
        }
    }

    private void findInterestingStrings() {
        String[] lines = fileContent.split("\n");

        for (String line : lines) {
            if (line.length() > 6 && line.length() < 256) {
                if (line.matches(".*(http|ftp|www|\\d{1,3}\\.\\d{1,3}).*") ||
                        line.matches(".*(passw|key|secret|token|api).*") ||
                        line.matches(".*(admin|root|user|login).*") ||
                        line.matches(".*(temp|tmp|cache|log).*") ||
                        line.matches(".*(cmd|exec|run|shell).*")) {
                    interestingStrings.add(line);
                }
            }
        }
    }

    public void printArtifacts() {
        System.out.println("=== URLs Found ===");
        printCollection(urls);

        // System.out.println("\n=== Filesystem Paths ===");
        // printCollection(filePaths);

        System.out.println("\n=== IP Addresses ===");
        printCollection(ipAddresses);

        System.out.println("\n=== Email Addresses ===");
        printCollection(emailAddresses);

        // System.out.println("\n=== Interesting Strings ===");
        // printCollection(interestingStrings);
    }

    private void printCollection(Set<String> collection) {
        if (collection.isEmpty()) {
            System.out.println("No items found");
        } else {
            collection.forEach(System.out::println);
        }
    }


    public PEArtifacts getArtifacts() {
        artifacts.setEmailAddresses(emailAddresses);
        artifacts.setUrls(urls);
        artifacts.setIpAddresses(ipAddresses);
        artifacts.setInterestingStrings(interestingStrings);
        return artifacts;
    }


}