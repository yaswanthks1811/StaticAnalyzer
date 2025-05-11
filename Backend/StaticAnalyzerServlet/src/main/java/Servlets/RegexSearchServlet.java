package Servlets;

import DAO.FileInfoDao;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@WebServlet("/analyze/regex")
public class RegexSearchServlet extends HttpServlet {
    private static final ObjectMapper mapper = new ObjectMapper();

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try (PrintWriter out = response.getWriter()) {
            // Read request body
            StringBuilder requestBody = new StringBuilder();
            try (BufferedReader reader = request.getReader()) {
                String line;
                while ((line = reader.readLine()) != null) {
                    requestBody.append(line);
                }
            }

            // Parse JSON request
            JsonNode jsonNode = mapper.readTree(requestBody.toString());
            String regexPattern = jsonNode.get("pattern").asText();
            String sha1 = jsonNode.get("sha1").asText();

            // Validate inputs
            if (regexPattern == null || regexPattern.trim().isEmpty()) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.println(mapper.writeValueAsString(Map.of("error", "Regex pattern cannot be empty")));
                return;
            }

            if (sha1 == null || sha1.trim().isEmpty()) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.println(mapper.writeValueAsString(Map.of("error", "SHA1 hash cannot be empty")));
                return;
            }

            // Get file data
            FileInfoDao fileInfoDao = new FileInfoDao();
            String filePath = fileInfoDao.getJsonFilePath(sha1);

            if (filePath == null) {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                out.println(mapper.writeValueAsString(Map.of("error", "File not found for the provided SHA1")));
                return;
            }

            // Read and parse JSON file
            String jsonString = new String(Files.readAllBytes(Paths.get(filePath)));
            JsonNode node = mapper.readTree(jsonString);

            if (!node.has("extractedStrings")) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.println(mapper.writeValueAsString(Map.of("error", "Invalid file format - missing allStrings field")));
                return;
            }

            String allStrings = node.get("extractedStrings").asText();

            // Perform regex search
            List<String> matches;
            try {
                matches = customRegexSearch(regexPattern, allStrings);
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.println(mapper.writeValueAsString(Map.of("error", "Invalid regex pattern: " + e.getMessage())));
                return;
            }

            // Prepare response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("matches", matches);
            responseData.put("count", matches.size());

            out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(responseData));

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            mapper.writeValue(response.getWriter(),
                    Map.of("error", "Server error: " + e.getMessage()));
        }
    }

    private List<String> customRegexSearch(String regex, String allStrings) throws Exception {
        List<String> matches = new ArrayList<>();

        // Compile pattern with case-insensitive flag as an example
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);

        // Split by line and search
        String[] lines = allStrings.split("\\r?\\n");
        for (String line : lines) {
            Matcher matcher = pattern.matcher(line);
            while (matcher.find()) {
                matches.add(matcher.group());
            }
        }

        return matches;
    }
}