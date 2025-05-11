//package Servlets;
//
//import DAO.FileInfoDao;
//import com.fasterxml.jackson.core.JsonFactory;
//import com.fasterxml.jackson.core.JsonParser;
//import com.fasterxml.jackson.core.JsonToken;
//import com.fasterxml.jackson.databind.JsonNode;
//import com.fasterxml.jackson.databind.ObjectMapper;
//
//import javax.servlet.ServletException;
//import javax.servlet.annotation.WebServlet;
//import javax.servlet.http.HttpServlet;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.*;
//import java.nio.file.Files;
//import java.nio.file.Paths;
//import java.sql.SQLException;
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//import java.util.regex.Matcher;
//import java.util.regex.Pattern;
//
//@WebServlet("/analyze/artifacts")
//public class ArtifactsServlet extends HttpServlet {
//    private static final Pattern URL_PATTERN = Pattern.compile(
//            "(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]");
//    private static final Pattern FILE_PATTERN = Pattern.compile(
//            "(?i)\\b[a-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*");
//    private static final Pattern IP_PATTERN = Pattern.compile(
//            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
//    private static final Pattern EMAIL_PATTERN = Pattern.compile(
//            "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}");
//    private static final Pattern REGISTRY_PATTERN = Pattern.compile(
//            "HKEY_[A-Z_]+\\\\[^\\\\]+(\\\\[^\\\\]+)*", Pattern.CASE_INSENSITIVE);
//    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
//            "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]",
//            Pattern.CASE_INSENSITIVE);
//    private static final Pattern API_PATTERN = Pattern.compile(
//            "\\b(?:Create|Open|Read|Write|Close|Delete|Find|Get|Set|Send|Receive|Put)[A-Z][a-zA-Z]+\\b",
//            Pattern.CASE_INSENSITIVE);
//    private static final Pattern METADATA_PATTERN = Pattern.compile(
//            "\\b(?:CompanyName|FileDescription|FileVersion|InternalName|LegalCopyright|" +
//                    "OriginalFilename|ProductName|ProductVersion|Assembly Version|BuildDate)\\b",
//            Pattern.CASE_INSENSITIVE);
//    private static final ObjectMapper mapper = new ObjectMapper();
//    private static final FileInfoDao fileInfoDao = new FileInfoDao();
//
//    public void toPost(HttpServletRequest request, HttpServletResponse response) throws IOException, SQLException {
//        List<String> results = new ArrayList<>();
//        BufferedReader reader = request.getReader();
//        StringBuilder requestBody = new StringBuilder();
//        String line;
//        while ((line = reader.readLine()) != null) {
//            requestBody.append(line);
//        }
//        JsonNode jsonNode = mapper.readTree(requestBody.toString());
//        int page = jsonNode.get("page").asInt();
//        int limit = jsonNode.get("limit").asInt();;
//        String type = jsonNode.get("type").asText();
//        String section = jsonNode.get("section").asText();
//        String sha1 = jsonNode.get("sha1").asText();
//
//        String filePath = fileInfoDao.getJsonFilePath(sha1);
//        if (filePath == null) {
//            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
//            return;
//        }
//        FileReader fileReader = new FileReader(filePath);
//        JsonFactory factory = new JsonFactory();
//        try (JsonParser parser = factory.createParser(new File(filePath))) {
//            int count = 0;
//            String pattern = type;
//            Pattern pattern1 = Pattern.compile(pattern);
//            while (!parser.isClosed()) {
//                JsonToken token = parser.nextToken();
//                if (JsonToken.FIELD_NAME.equals(token) && section.equals(parser.getCurrentName())) {
//                    parser.nextToken(); // move to value
//                    String temp = parser.getValueAsString();
//                    if(pattern1.matcher(temp).matches()) {
//                        results.add(temp);
//                        count++;
//                    }
//                }
//            }
//        }
//
//    }
//}
//
//
//
//
//
