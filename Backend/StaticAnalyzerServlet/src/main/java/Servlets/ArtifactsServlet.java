package Servlets;

import DAO.FileInfoDao;
import Utilities.JsonCache;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
@WebServlet("/analyze/artifacts")
public class ArtifactsServlet extends HttpServlet {
    private static final ObjectMapper mapper = new ObjectMapper();
    private final Logger logger = Logger.getLogger(ArtifactsServlet.class.getName());
    private int version = 0;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            String sha1 = request.getParameter("sha1");
            boolean forceLatin1 = Boolean.parseBoolean(request.getParameter("forceLatin1"));
            String pattern = request.getParameter("pattern");
            this.version = Integer.parseInt(request.getParameter("version"));

            if (sha1 == null || sha1.isEmpty()) {
                sendError(response, "Missing required parameter: sha1", HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
            JsonNode rootNode=null;
            if(JsonCache.contains(sha1+'v'+version) ) {
                logger.info("Response from Cache");
                rootNode = JsonCache.get(sha1+'v'+version);
            }
            else {
                logger.info("Response from Json File");
                FileInfoDao fileInfoDao = new FileInfoDao();
                String filePath = fileInfoDao.getArtifactsFilePath(sha1,version);
                if (filePath == null) {
                    sendError(response, "File not found", HttpServletResponse.SC_NOT_FOUND);
                    return;
                }

                rootNode = readJsonFile(sha1, filePath, forceLatin1);
            }

            if (pattern != null && !pattern.isEmpty()) {
                handleRegexSearch(response, rootNode, request);
            } else {
                handleArtifactRequest(response, rootNode, request);
            }

        } catch (Exception e) {
            sendError(response, "Server error: " + e.getMessage(), HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private void handleArtifactRequest(HttpServletResponse response, JsonNode rootNode, HttpServletRequest request)
            throws IOException {

        int page = parseIntOrDefault(request.getParameter("page"), 1);
        int limit = parseIntOrDefault(request.getParameter("limit"), 10);
        String section = Optional.ofNullable(request.getParameter("section")).orElse("all");
        String searchTerm = request.getParameter("searchTerm");
        String targetArtifactType = request.getParameter("targetArtifactType");
        boolean initialRequest = Boolean.parseBoolean(request.getParameter("initialRequest"));

        String artifactTypesParam = request.getParameter("artifactTypes");
        List<String> artifactTypes = new ArrayList<>();
        if (artifactTypesParam != null && !artifactTypesParam.isEmpty()) {
            artifactTypes = Arrays.asList(artifactTypesParam.split(","));
        }

        // Validate inputs
        page = Math.max(1, page);
        limit = Math.max(1, Math.min(limit, 100));
        int offset = (page - 1) * limit;

        // Prepare response
        ObjectNode responseNode = mapper.createObjectNode();
        responseNode.put("page", page);
        responseNode.put("limit", limit);
        responseNode.put("section", section);
        if (targetArtifactType != null) {
            responseNode.put("targetArtifactType", targetArtifactType);
        }

        // Only send available sections/types on initial request
        if (initialRequest) {
            ArrayNode sectionsArray = responseNode.putArray("availableSections");
            rootNode.get("artifacts").fieldNames().forEachRemaining(sectionsArray::add);
        }

        // Filter by section

        JsonNode sectionNode = section.equals("allSections") ? rootNode.get("artifacts") :
                mapper.createObjectNode().set(section, rootNode.get("artifacts").get(section));

        ObjectNode artifactsBlock = mapper.createObjectNode();
        ObjectNode artifactsSections = mapper.createObjectNode();

        int totalItems = 0;

        // Process each section
        Iterator<String> sectionNames = sectionNode.fieldNames();
        ObjectNode sectionBlock =mapper.createObjectNode();
        while (sectionNames.hasNext()) {

            String sectionName = sectionNames.next();
            JsonNode artifactsNode = sectionNode.get(sectionName).get(0);

            // Only send available types on initial request
            if (initialRequest) {
                ObjectNode artifactsResponse = responseNode.putObject("artifacts");
                ObjectNode sectionResponse = artifactsResponse.putObject(sectionName);
                ArrayNode availableTypes = sectionResponse.putArray("availableTypes");
                artifactsNode.fieldNames().forEachRemaining(availableTypes::add);
                continue;
            }

            // Process each artifact type
            Iterator<String> artifactNames = artifactsNode.fieldNames();



            while (artifactNames.hasNext()) {
                String artifactName = artifactNames.next();

                // Skip if we're targeting a specific artifact type and this isn't it
                if (targetArtifactType != null && !targetArtifactType.equals(artifactName)) {
                    continue;
                }

                // Skip if filtering by artifact types and this isn't one of them
                if (!artifactTypes.isEmpty() && !artifactTypes.contains(artifactName)) {
                    continue;
                }

                JsonNode itemsNode = artifactsNode.get(artifactName);
                if (!itemsNode.isArray()) continue;

//                ObjectNode sectionResponse = artifactsResponse.putObject(sectionName);
                ArrayNode paginatedItems = mapper.createArrayNode();

                // Apply search filter if needed
                List<JsonNode> filteredItems = new ArrayList<>();
                // Apply pagination
                int startIndex = Math.min(offset, itemsNode.size());
                int endIndex = Math.min(offset + limit, itemsNode.size());
                int count =0;
                if (searchTerm != null && !searchTerm.isEmpty()) {
                    for (JsonNode itemNode : itemsNode) {
                        if (itemNode.asText().toLowerCase().contains(searchTerm.toLowerCase())) {
                            filteredItems.add(itemNode);
                        }
                    }
                    totalItems = filteredItems.size();
                    startIndex = Math.min(offset, filteredItems.size());
                    endIndex = Math.min(offset + limit, filteredItems.size());
                    for (int i = startIndex; i < endIndex; i++) {
                        paginatedItems.add(filteredItems.get(i));
                    }
                } else {
                    for (int i = startIndex; i <endIndex ; i++) {
                        paginatedItems.add(itemsNode.get(i));
                    }
                    totalItems = itemsNode.size();
                }


                // Add pagination info for this artifact type
                ObjectNode paginationInfo = mapper.createObjectNode();
                paginationInfo.put("page", page);
                paginationInfo.put("limit", limit);
                paginationInfo.put("totalItems", totalItems);
                paginationInfo.put("totalPages", (int) Math.ceil((double) totalItems / limit));

                artifactsSections.put(artifactName, paginatedItems);
                artifactsSections.set(artifactName + "_pagination", paginationInfo);
                sectionBlock.put(sectionName, artifactsSections);
                responseNode.put("artifacts",sectionBlock);
                artifactsBlock.put("artifacts", sectionBlock);

            }
        }

        responseNode.put("totalItems", totalItems);
        responseNode.put("totalPages", (int) Math.ceil((double) totalItems / limit));

        mapper.writeValue(response.getWriter(), responseNode);
    }

    private void handleRegexSearch(HttpServletResponse response, JsonNode rootNode, HttpServletRequest request)
            throws IOException {

        String pattern = request.getParameter("pattern");
        int page = parseIntOrDefault(request.getParameter("page"), 1);
        int limit = parseIntOrDefault(request.getParameter("limit"), 10);
        String searchTerm = request.getParameter("searchTerm");

        if (!rootNode.has("extractedStrings")) {
            sendError(response, "No extracted strings found", HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        String allStrings = rootNode.get("extractedStrings").asText();
        Pattern compiledPattern;

        try {
            compiledPattern = Pattern.compile(pattern);
        } catch (PatternSyntaxException e) {
            sendError(response, "Invalid regex pattern: " + e.getMessage(), HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        List<String> allMatches = new ArrayList<>();
        Matcher matcher = compiledPattern.matcher(allStrings);
        while (matcher.find()) {
            String match = matcher.group();
            if (searchTerm == null || searchTerm.isEmpty() || match.toLowerCase().contains(searchTerm.toLowerCase())) {
                allMatches.add(match);
            }
        }

        int totalItems = allMatches.size();
        int totalPages = (int) Math.ceil((double) totalItems / limit);
        int fromIndex = (page - 1) * limit;
        int toIndex = Math.min(fromIndex + limit, totalItems);
        List<String> paginatedMatches = allMatches.subList(fromIndex, toIndex);

        ObjectNode responseNode = mapper.createObjectNode();
        responseNode.put("page", page);
        responseNode.put("limit", limit);
        responseNode.put("totalItems", totalItems);
        responseNode.put("totalPages", totalPages);

        ArrayNode matchesArray = responseNode.putArray("matches");
        paginatedMatches.forEach(matchesArray::add);

        mapper.writeValue(response.getWriter(), responseNode);
    }

    private int parseIntOrDefault(String value, int defaultValue) {
        try {
            return Integer.parseInt(value);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private JsonNode readJsonFile(String sha1, String filePath, boolean forceLatin1) throws IOException {
        if (!forceLatin1 && JsonCache.contains(sha1+'v'+version)) {
            System.out.println("From Cache");
            return JsonCache.get(sha1+'v'+version);
        }

        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        JsonNode rootNode;

        if (forceLatin1) {
            rootNode = mapper.readTree(new String(fileBytes, StandardCharsets.ISO_8859_1));
        } else {
            try {
                rootNode = mapper.readTree(new String(fileBytes, StandardCharsets.UTF_8));
            } catch (JsonParseException e) {
                rootNode = mapper.readTree(new String(fileBytes, StandardCharsets.ISO_8859_1));
            }
        }

        if (!forceLatin1) {
            JsonCache.put(sha1+'v'+version, rootNode);
        }

        return rootNode;
    }

    private void sendError(HttpServletResponse response, String message, int statusCode) throws IOException {
        response.setStatus(statusCode);
        ObjectNode errorNode = mapper.createObjectNode();
        errorNode.put("error", message);
        mapper.writeValue(response.getWriter(), errorNode);
    }
}