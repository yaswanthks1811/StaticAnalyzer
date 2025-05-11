package Analyzers;

import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PEArtifactExtractor implements Serializable {
    private final byte[] fileBytes;
    private final Map<String, String> sectionStrings;
    private final Map<String, Map<String, Set<String>>> sectionArtifacts;

    // Regex patterns for artifact detection
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]");
    private static final Pattern FILE_PATTERN = Pattern.compile(
            "(?i)\\b[a-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*");
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}");
    private static final Pattern REGISTRY_PATTERN = Pattern.compile(
            "HKEY_[A-Z_]+\\\\[^\\\\]+(\\\\[^\\\\]+)*", Pattern.CASE_INSENSITIVE);
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern API_PATTERN = Pattern.compile(
            "\\b(?:Create|Open|Read|Write|Close|Delete|Find|Get|Set|Send|Receive|Put)[A-Z][a-zA-Z]+\\b",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern METADATA_PATTERN = Pattern.compile(
            "\\b(?:CompanyName|FileDescription|FileVersion|InternalName|LegalCopyright|" +
                    "OriginalFilename|ProductName|ProductVersion|Assembly Version|BuildDate)\\b",
            Pattern.CASE_INSENSITIVE);

    public PEArtifactExtractor(byte[] fileBytes) throws IOException {
        this.fileBytes = fileBytes;
        StringsExtractFromSection extractFromSection = new StringsExtractFromSection(fileBytes);
        this.sectionStrings = extractFromSection.getSectionStrings();
        this.sectionArtifacts = new LinkedHashMap<>();
        analyzeAllSections();
        analyzeWholeFile();
    }

    private void analyzeAllSections() {
        for (Map.Entry<String, String> entry : sectionStrings.entrySet()) {
            String sectionName = entry.getKey();
            String content = entry.getValue();

            Map<String, Set<String>> artifacts = new LinkedHashMap<>();
            artifacts.put("urls", extractUrls(content));
            artifacts.put("filePaths", extractFilePaths(content));
            artifacts.put("ipAddresses", extractIpAddresses(content));
            artifacts.put("emailAddresses", extractEmailAddresses(content));
            artifacts.put("registryKeys", extractRegistryKeys(content));
            artifacts.put("domains", extractDomains(content));
            artifacts.put("apiCalls", extractApiCalls(content));
            artifacts.put("metadata", extractMetadata(content));
            artifacts.put("interestingStrings", findInterestingStrings(content));

            sectionArtifacts.put(sectionName, artifacts);
        }
    }

    private void analyzeWholeFile(){
        String content = extractAllStrings();

        Map<String, Set<String>> artifacts = new LinkedHashMap<>();
        artifacts.put("urls", extractUrls(content));
        artifacts.put("filePaths", extractFilePaths(content));
        artifacts.put("ipAddresses", extractIpAddresses(content));
        artifacts.put("emailAddresses", extractEmailAddresses(content));
        artifacts.put("registryKeys", extractRegistryKeys(content));
        artifacts.put("domains", extractDomains(content));
        artifacts.put("apiCalls", extractApiCalls(content));
        artifacts.put("metadata", extractMetadata(content));
        artifacts.put("interestingStrings", findInterestingStrings(content));

        sectionArtifacts.put("all", artifacts);

    }

    public Map<String, List<Map<String, List<String>>>> getStructuredArtifacts() {
        Map<String, List<Map<String, List<String>>>> result = new LinkedHashMap<>();

        for (Map.Entry<String, Map<String, Set<String>>> entry : sectionArtifacts.entrySet()) {
            String sectionName = entry.getKey();
            Map<String, Set<String>> artifacts = entry.getValue();

            Map<String, List<String>> artifactListMap = new LinkedHashMap<>();
            for (Map.Entry<String, Set<String>> artifactEntry : artifacts.entrySet()) {
                artifactListMap.put(artifactEntry.getKey(), new ArrayList<>(artifactEntry.getValue()));
            }

            List<Map<String, List<String>>> sectionList = new ArrayList<>();
            sectionList.add(artifactListMap);
            result.put(sectionName, sectionList);
        }

        return result;
    }

    public String extractAllStrings() {
        StringBuilder sb = new StringBuilder();

        // Try UTF-8 decoding first
        String utf8Content = new String(fileBytes, StandardCharsets.UTF_8);
        sb.append(utf8Content);

        // Try UTF-16LE decoding (common in Windows executables)
        String utf16Content = new String(fileBytes, StandardCharsets.UTF_16LE);
        if (utf16Content.length() > 0) {
            sb.append("\n").append(utf16Content);
        }

        return sb.toString();
    }

    // Individual artifact extraction methods
    private Set<String> extractUrls(String content) {
        Set<String> urls = new LinkedHashSet<>();
        Matcher matcher = URL_PATTERN.matcher(content);
        while (matcher.find()) {
            String url = matcher.group();
            if (!url.contains("example.com")) {
                urls.add(url);
            }
        }
        return urls;
    }

    private Set<String> extractFilePaths(String content) {
        Set<String> paths = new LinkedHashSet<>();
        Matcher matcher = FILE_PATTERN.matcher(content);
        while (matcher.find()) {
            paths.add(matcher.group());
        }
        return paths;
    }

    private Set<String> extractIpAddresses(String content) {
        Set<String> ips = new LinkedHashSet<>();
        Matcher matcher = IP_PATTERN.matcher(content);
        while (matcher.find()) {
            ips.add(matcher.group());
        }
        return ips;
    }

    private Set<String> extractEmailAddresses(String content) {
        Set<String> emails = new LinkedHashSet<>();
        Matcher matcher = EMAIL_PATTERN.matcher(content);
        while (matcher.find()) {
            String email = matcher.group();
            if (!email.endsWith("@example.com")) {
                emails.add(email);
            }
        }
        return emails;
    }

    private Set<String> extractRegistryKeys(String content) {
        Set<String> keys = new LinkedHashSet<>();
        Matcher matcher = REGISTRY_PATTERN.matcher(content);
        while (matcher.find()) {
            keys.add(matcher.group());
        }
        return keys;
    }

    private Set<String> extractDomains(String content) {
        Set<String> domains = new LinkedHashSet<>();
        Matcher matcher = DOMAIN_PATTERN.matcher(content);
        while (matcher.find()) {
            domains.add(matcher.group().toLowerCase());
        }
        return domains;
    }

    private Set<String> extractApiCalls(String content) {
        Set<String> apis = new LinkedHashSet<>();
        Matcher matcher = API_PATTERN.matcher(content);
        while (matcher.find()) {
            apis.add(matcher.group());
        }
        return apis;
    }

    private Set<String> extractMetadata(String content) {
        Set<String> metadata = new LinkedHashSet<>();
        Matcher matcher = METADATA_PATTERN.matcher(content);
        while (matcher.find()) {
            metadata.add(matcher.group());
        }
        return metadata;
    }

    private Set<String> findInterestingStrings(String content) {
        Set<String> interesting = new LinkedHashSet<>();
        String[] lines = content.split("\n");
        for (String line : lines) {
            if (line.length() > 6 && line.length() < 256) {
                if (line.matches(".*(http|ftp|www).*") ||
                        line.matches(".*(passw|key|secret|token|api).*") ||
                        line.matches(".*(admin|root|user|login).*") ||
                        line.matches(".*(temp|tmp|cache|log).*") ||
                        line.matches(".*(cmd|exec|run|shell).*")) {
                    interesting.add(line);
                }
            }
        }
        return interesting;
    }



    public void printArtifacts() {
        Map<String, List<Map<String, List<String>>>> artifacts = getStructuredArtifacts();

        for (Map.Entry<String, List<Map<String, List<String>>>> entry : artifacts.entrySet()) {
            System.out.println("\n=== Section: " + entry.getKey() + " ===");

            for (Map<String, List<String>> artifactMap : entry.getValue()) {
                for (Map.Entry<String, List<String>> artifactEntry : artifactMap.entrySet()) {
                    System.out.println("  " + artifactEntry.getKey() + ": " + artifactEntry.getValue().size());
                    if (!artifactEntry.getValue().isEmpty()) {
                        System.out.println("    " + String.join("\n    ", artifactEntry.getValue()));
                    }
                }
            }
        }
    }
}