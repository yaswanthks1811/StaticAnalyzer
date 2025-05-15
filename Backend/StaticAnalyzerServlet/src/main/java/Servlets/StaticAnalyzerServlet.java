package Servlets;

import Analyzers.*;
import DAO.*;
import Utilities.JsonCache;
import Utilities.Utils;
import Utilities.Version;
import Utilities.AnalysisCache;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import Bean.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.SQLException;
import java.util.*;
import java.util.logging.Logger;
import javax.servlet.*;
import javax.servlet.annotation.*;
import javax.servlet.http.*;

@WebServlet("/analyze")
@MultipartConfig(
        fileSizeThreshold = 1024 * 1024 * 10,
        maxFileSize = 1024 * 1024 * 180,
        maxRequestSize = 1024 * 1024 * 180
)
public class StaticAnalyzerServlet extends HttpServlet {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String ANALYSIS_RESULTS_PATH = "C:\\Users\\yaswant-pt7919\\Malware Analysis\\Analysis Results";
    private static final String ARTIFACTS_PATH = "C:\\Users\\yaswant-pt7919\\Malware Analysis\\Artifacts";
    private static int fileId;
    private final Logger logger = Logger.getLogger(StaticAnalyzerServlet.class.getName());
    private int analyzerVersion = Version.getAnalyzerVersion();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        FileInfoDao fileInfoDao = new FileInfoDao();

        try {
            if (request.getContentType().contains("application/json")) {
                JsonNode jsonNode = objectMapper.readTree(request.getReader());
                String sha1 = jsonNode.has("sha1") ? jsonNode.get("sha1").asText() : null;
                int version = jsonNode.has("version") ? jsonNode.get("version").asInt() :analyzerVersion;

                if (sha1 == null || sha1.isEmpty()) {
                    sendError(response, out, "Invalid SHA1 hash", HttpServletResponse.SC_BAD_REQUEST);
                    return;
                }

                // Check cache first

                if (AnalysisCache.contains(sha1+'v'+version) ) {
                        objectMapper.writeValue(out, AnalysisCache.get(sha1+'v'+version));
                        logger.info("Serving from LRI cache for SHA1: " + sha1);
                        return;
                }

                //Check sha1 in db
                if (!fileInfoDao.isSha1Present(sha1,version)) {
                    logger.info("No Sha found in DB");
                    sendError(response, out, "No analysis found for the provided SHA1 hash", HttpServletResponse.SC_NOT_FOUND);
                    return;
                }
                //Get the Analysis Report File Path from db
                String filePath = fileInfoDao.getJsonFilePath(sha1,version);
                if (filePath == null || filePath.isEmpty()) {
                    sendError(response, out, "Analysis data not found", HttpServletResponse.SC_NOT_FOUND);
                    return;
                }

                String jsonContent = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
                JsonNode resultNode = objectMapper.readTree(jsonContent);

                // Add to cache
                AnalysisCache.put(sha1+'v'+resultNode.get("analyzerVersion"), resultNode);
                logger.info("Serving from DB for SHA1: " + sha1);

                out.println(jsonContent);
            } else {
                Part filePart = request.getPart("exeFile");
                if (filePart == null) {
                    sendError(response, out, "No file uploaded", HttpServletResponse.SC_BAD_REQUEST);
                    return;
                }

                Path tempFile = Files.createTempFile("upload-", ".tmp");
                try {
                    try (InputStream input = filePart.getInputStream();
                         OutputStream output = Files.newOutputStream(tempFile)) {
                        input.transferTo(output);
                    }

                    byte[] fileBytes = Files.readAllBytes(tempFile);
                    String fileName = filePart.getSubmittedFileName();
                    String sha1Hash = Utils.calculateHash(fileBytes, "SHA1");

                    // Check cache for existing analysis
                    if (AnalysisCache.contains(sha1Hash+'v'+analyzerVersion) ) {
                        objectMapper.writeValue(out, AnalysisCache.get(sha1Hash+'v'+analyzerVersion));
                        logger.info("Serving from LRI cache for SHA1: " + sha1Hash);
                        return;
                    }

                    // Check sha1 in db
                    if (fileInfoDao.isSha1Present(sha1Hash,analyzerVersion) ) {

                        String existingPath = fileInfoDao.getJsonFilePath(sha1Hash,analyzerVersion);
                        String jsonContent = new String(Files.readAllBytes(Paths.get(existingPath)), StandardCharsets.UTF_8);
                        JsonNode resultNode = objectMapper.readTree(jsonContent);

                        // Add to cache
                        AnalysisCache.put(sha1Hash+'v'+resultNode.get("analyzerVersion"), resultNode);
                        logger.info("Serving from DB for SHA1: " + sha1Hash);
                        out.println(jsonContent);
                        return;
                    }

                    // Perform analysis
                    Map<String, Object> analysisResults = performAnalysis(fileBytes, fileName, fileInfoDao);
                    String jsonResponse = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(analysisResults);
                    JsonNode resultNode = objectMapper.readTree(jsonResponse);

                    // Add to cache
                    AnalysisCache.put(sha1Hash+'v'+Version.getAnalyzerVersion(), resultNode);

                    // Save results to filesystem
                    saveResults(analysisResults, fileName ,fileBytes, fileInfoDao,sha1Hash);

                    out.println(jsonResponse);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
                finally {
                    filePart.delete();
                    Files.deleteIfExists(tempFile);
                }
            }
        } catch (Exception e) {
            sendError(response, out, "Analysis failed: " + e.getMessage(), HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            e.printStackTrace();

        }
    }


    private Map<String, Object> performAnalysis(byte[] fileBytes, String fileName,
                                                 FileInfoDao fileInfoDao) throws Exception {
        Map<String, Object> results = new LinkedHashMap<>();
        results.put("filename", fileName);
        results.put("analyzerVersion", Version.getAnalyzerVersion());

        // General File analysis
        PEFileAnalyzer fileAnalyzer = new PEFileAnalyzer(fileBytes, fileName);
        PEFileInfo fileInfo = fileAnalyzer.getPEFileInfo();
        this.fileId= fileInfoDao.insertFile(fileInfo);
        results.put("pe_fileinfo", fileInfo);

        // PE Static Analysis
        PEStaticInfo peStaticInfo = new PEInfoParser().getPEInfo(fileBytes);
        results.put("static_info", peStaticInfo);
        new PEStaticInfoDao().insertPEStaticInfo(fileId, peStaticInfo);

        // Data Directories
        List<DataDirectory> dataDirectories = new PEDataDirectoryAnalyzer(fileBytes).getDirectories();
        results.put("data_directories", dataDirectories);
        new DataDirectoriesDao().insertDataDirectories(fileId, dataDirectories);

        // Imports/Exports
        results.put("imports", new PEImportsParser().parse(fileBytes));
        results.put("exports", new PEExportsParser().parse(fileBytes));

        // Sections
        List<PESection> sections = new PESectionAnalyzer(fileBytes).getSections();
        results.put("sections", sections);
        new PESectionDao().insertSections(fileId, sections);

        // Resources
        results.put("resources", new PEResourceAnalyzer(fileBytes).getResources());

        // Authenticode
        PEAuthenticodeVerifier authenticodeVerifier = new PEAuthenticodeVerifier();
        authenticodeVerifier.analyze(fileBytes);
        results.put("authenticode_info", authenticodeVerifier.getPeAuthenticodeInfo());
        new AuthenticodeInfoDao().insertAuthenticodeInfo(fileId, authenticodeVerifier.getPeAuthenticodeInfo());

        return results;
    }

    private void saveResults(Map<String, Object> analysisResults,String fileName,
                             byte[] fileBytes, FileInfoDao fileInfoDao, String sha1Hash) throws IOException, SQLException {
        String baseName =fileName.replace(".exe", "");
        int analyzerVersion = Version.getAnalyzerVersion();

        // Save main analysis

        //Create file if that file does not exist and save the results
        Path analysisDir = Paths.get(ANALYSIS_RESULTS_PATH);
        if (!Files.exists(analysisDir)) Files.createDirectories(analysisDir);
        Path analysisFile = analysisDir.resolve(baseName + "_v" + analyzerVersion + ".json");
        Files.write(analysisFile, objectMapper.writerWithDefaultPrettyPrinter()
                .writeValueAsString(analysisResults).getBytes());

        // Save artifacts
        Map<String, Object> artifacts = new LinkedHashMap<>();
        artifacts.put("analyzerVersion", analyzerVersion);
        //All artifacts
        PEArtifactExtractor artifactExtractor = new PEArtifactExtractor(fileBytes);
        artifacts.put("artifacts", artifactExtractor.getStructuredArtifacts());
        //All Extracted strings from exe file
        ExtractStrings extractStrings = new ExtractStrings(fileBytes);
        artifacts.put("extractedStrings", extractStrings.extractAllStrings());
        String artifactsResponse = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(analysisResults);
        JsonNode resultNode = objectMapper.readTree(artifactsResponse);

        //Add to cache
//        JsonCache.put(sha1Hash,resultNode);

        //Save as File
        Path artifactsDir = Paths.get(ARTIFACTS_PATH);
        if (!Files.exists(artifactsDir)) Files.createDirectories(artifactsDir);
        Path artifactsFile = artifactsDir.resolve(baseName + "_v" + analyzerVersion + "_Artifacts.json");
        Files.write(artifactsFile, objectMapper.writerWithDefaultPrettyPrinter()
                .writeValueAsString(artifacts).getBytes());

        //Updating file paths to db
        fileInfoDao.updatePaths(fileId, analysisFile.toString(), artifactsFile.toString());
    }

    private void sendError(HttpServletResponse response, PrintWriter out, String message, int statusCode) {
        response.setStatus(statusCode);
        try {
            out.println(objectMapper.writeValueAsString(Map.of("error", message)));
        } catch (Exception e) {
            out.println("{\"error\": \"Failed to generate error message\"}");
        }
    }
}