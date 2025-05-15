package Analyzers;

import Bean.PEArtifacts;

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

    public Map<String, Object> getFilteredArtifacts(PEArtifacts filter) {
        Map<String, Object> response = new LinkedHashMap<>();

        // Get the requested section data
        Map<String, Set<String>> sectionData = sectionArtifacts.getOrDefault(
                filter.getSection(),
                Collections.emptyMap()
        );

        // Apply filters
        Map<String, List<String>> filteredResults = new LinkedHashMap<>();
        int totalItems = 0;

        if (filter.getArtifactTypes() == null || filter.getArtifactTypes().isEmpty()) {
            // Return all artifact types if none specified
            for (Map.Entry<String, Set<String>> entry : sectionData.entrySet()) {
                List<String> items = applySearchFilter(new ArrayList<>(entry.getValue()), filter.getSearchTerm());
                filteredResults.put(entry.getKey(), items);
                totalItems += items.size();
            }
        } else {
            // Return only requested artifact types
            for (String type : filter.getArtifactTypes()) {
                if (sectionData.containsKey(type)) {
                    List<String> items = applySearchFilter(
                            new ArrayList<>(sectionData.get(type)),
                            filter.getSearchTerm()
                    );
                    filteredResults.put(type, items);
                    totalItems += items.size();
                }
            }
        }

        // Apply pagination
        Map<String, List<String>> paginatedResults = new LinkedHashMap<>();
        int itemsProcessed = 0;
        int itemsRemaining = filter.getLimit();
        int skipItems = (filter.getPage() - 1) * filter.getLimit();

        for (Map.Entry<String, List<String>> entry : filteredResults.entrySet()) {
            List<String> allItems = entry.getValue();
            List<String> paginatedItems = new ArrayList<>();

            // Skip items from previous pages
            if (skipItems > 0) {
                int skip = Math.min(skipItems, allItems.size());
                allItems = allItems.subList(skip, allItems.size());
                skipItems -= skip;
                continue;
            }

            // Take items for current page
            if (itemsRemaining > 0 && !allItems.isEmpty()) {
                int take = Math.min(itemsRemaining, allItems.size());
                paginatedItems = allItems.subList(0, take);
                itemsRemaining -= take;
                itemsProcessed += take;
            }

            paginatedResults.put(entry.getKey(), paginatedItems);
        }

        // Calculate total pages
        int totalPages = (int) Math.ceil((double) totalItems / filter.getLimit());

        // Build response
        response.put("page", filter.getPage());
        response.put("limit", filter.getLimit());
        response.put("totalItems", totalItems);
        response.put("totalPages", totalPages);
        response.put("artifacts", paginatedResults);
        response.put("section", filter.getSection());

        return response;
    }

    private List<String> applySearchFilter(List<String> items, String searchTerm) {
        if (searchTerm == null || searchTerm.trim().isEmpty()) {
            return items;
        }

        String lowerSearch = searchTerm.toLowerCase();
        List<String> filtered = new ArrayList<>();

        for (String item : items) {
            if (item.toLowerCase().contains(lowerSearch)) {
                filtered.add(item);
            }
        }

        return filtered;
    }
    public PEArtifactExtractor(byte[] fileBytes) throws IOException {
        this.fileBytes = fileBytes;
        ExtractStrings extract = new ExtractStrings(fileBytes);
        this.sectionStrings = extract.getSectionStrings();
        this.sectionArtifacts = new LinkedHashMap<>();
        analyzeAllSections();
        analyzeWholeFile(extract);
    }

    private void analyzeAllSections() {
        for (Map.Entry<String, String> entry : sectionStrings.entrySet()) {
            String sectionName = entry.getKey();
            String content = entry.getValue();

            Map<String, Set<String>> artifacts = new LinkedHashMap<>();
            Set<String > temp = new LinkedHashSet<>();
            temp = extractUrls(content);
            if (!temp.isEmpty()) {
                artifacts.put("urls", temp);
            }
            temp = extractFilePaths(content);
            if (!temp.isEmpty()) {
                artifacts.put("filePaths", temp);
            }
            temp =extractIpAddresses(content);
            if (!temp.isEmpty()) {
                artifacts.put("ipAddresses", temp);
            }
            temp=extractEmailAddresses(content);
            if (!temp.isEmpty()) {
                artifacts.put("emailAddresses", temp);
            }
            temp = extractRegistryKeys(content);
            if (!temp.isEmpty()) {
                artifacts.put("registryKeys", temp);
            }
            temp = extractDomains(content);
            if (!temp.isEmpty()) {
                artifacts.put("domains", temp);
            }
            temp = extractApiCalls(content);
            if (!temp.isEmpty()) {
                artifacts.put("apiCalls", temp);
            }
            temp = extractMetadata(content);
            if (!temp.isEmpty()) {
                artifacts.put("metadata", temp);
            }
            temp =findInterestingStrings(content);
            if (!temp.isEmpty()) {
                artifacts.put("interestingStrings", temp);
            }
            sectionArtifacts.put(sectionName, artifacts);
        }
    }

    private void analyzeWholeFile(ExtractStrings extract){
        String content = extract.extractAllStrings();

        Map<String, Set<String>> artifacts = new LinkedHashMap<>();
        Set<String > temp = new LinkedHashSet<>();
        temp = extractUrls(content);
        if (!temp.isEmpty()) {
            artifacts.put("urls", temp);
        }
        temp = extractFilePaths(content);
        if (!temp.isEmpty()) {
            artifacts.put("filePaths", temp);
        }
        temp =extractIpAddresses(content);
        if (!temp.isEmpty()) {
            artifacts.put("ipAddresses", temp);
        }
        temp=extractEmailAddresses(content);
        if (!temp.isEmpty()) {
            artifacts.put("emailAddresses", temp);
        }
        temp = extractRegistryKeys(content);
        if (!temp.isEmpty()) {
            artifacts.put("registryKeys", temp);
        }
        temp = extractDomains(content);
        if (!temp.isEmpty()) {
            artifacts.put("domains", temp);
        }
        temp = extractApiCalls(content);
        if (!temp.isEmpty()) {
            artifacts.put("apiCalls", temp);
        }
        temp = extractMetadata(content);
        if (!temp.isEmpty()) {
            artifacts.put("metadata", temp);
        }
        temp =findInterestingStrings(content);
        if (!temp.isEmpty()) {
            artifacts.put("interestingStrings", temp);
        }

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