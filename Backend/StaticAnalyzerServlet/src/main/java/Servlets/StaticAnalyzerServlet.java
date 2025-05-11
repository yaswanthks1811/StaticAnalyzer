package Servlets;

import Analyzers.*;
import DAO.*;
import Utilities.Version;
import com.fasterxml.jackson.databind.ObjectMapper;
import Bean.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

@WebServlet("/analyze")
@MultipartConfig(
        fileSizeThreshold = 1024 * 1024 * 1, // 1 MB
        maxFileSize = 1024 * 1024 * 80,
        maxRequestSize = 1024 * 1024 * 100
)
public class StaticAnalyzerServlet extends HttpServlet {

    private static final ObjectMapper objectMapper = new ObjectMapper();



    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        System.out.println("doPost");

        PrintWriter out = response.getWriter();

        try {
            Part filePart = request.getPart("exeFile");
            String fileName = filePart.getSubmittedFileName();
            System.out.println(filePart.toString());
            if (fileName == null || fileName.isEmpty()) {
                sendError(response, out, "No file uploaded", HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            if (!fileName.toLowerCase().endsWith(".exe") && !fileName.toLowerCase().endsWith(".dll")) {
                sendError(response, out, "Only EXE/DLL files are supported", HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            // Read file content
            byte[] fileBytes = filePart.getInputStream().readAllBytes();
            // Perform all analyses
            Map<String, Object> analysisResults = new LinkedHashMap<>();
            analysisResults.put("filename", fileName);

            // General File Analysis
            PEFileAnalyzer fileAnalyzer = new PEFileAnalyzer(fileBytes,fileName);
            PEFileInfo peFileInfo = fileAnalyzer.getPEFileInfo();
            FileInfoDao fileInfoDao = new FileInfoDao();
            peFileInfo.setFileName(fileName);
            //checking the file is Already analyzed
            boolean shouldInsert = false;
            if(fileInfoDao.isSha1Present(peFileInfo.getSha1Hash())){
                if(Version.getAnalyzerVersion()!=fileInfoDao.getAnalyzerVersion(peFileInfo.getSha1Hash())){
                    shouldInsert = true;
                }
            }
            else {
                shouldInsert = true;
            }


            if(shouldInsert){
                analysisResults.put("analyzerVersion", Version.getAnalyzerVersion());
                analysisResults.put("pe_fileinfo", peFileInfo);
                int file_id = fileInfoDao.insertFile(peFileInfo);

                // Static PE File Analysis
                PEInfoParser peInfoParser = new PEInfoParser();
                PEStaticInfo peStaticInfo = peInfoParser.getPEInfo(fileBytes);
                analysisResults.put("static_info",peStaticInfo);
                PEStaticInfoDao peStaticInfoDao = new PEStaticInfoDao();
                peStaticInfoDao.insertPEStaticInfo(file_id,peStaticInfo);

                //Directory Analysis
                PEDataDirectoryAnalyzer dataDirectoryAnalyzer = new PEDataDirectoryAnalyzer(fileBytes);
                List<DataDirectory> dataDirectories = dataDirectoryAnalyzer.getDirectories();
                analysisResults.put("data_directories",dataDirectories);
                DataDirectoriesDao dataDirectoriesDao = new DataDirectoriesDao();
                dataDirectoriesDao.insertDataDirectories(file_id,dataDirectories);

                //  Import/Export Analysis
                PEImportsParser peImportsParser = new PEImportsParser();
                analysisResults.put("imports", peImportsParser.parse(fileBytes));

                PEExportsParser peExportsParser = new PEExportsParser();
                analysisResults.put("exports",peExportsParser.parse(fileBytes));

                //  Section Analysis
                PESectionAnalyzer sectionInfo = new PESectionAnalyzer(fileBytes);
                List<PESection> sections = sectionInfo.getSections();
                analysisResults.put("sections", sections);
                PESectionDao peSectionDao = new PESectionDao();
                peSectionDao.insertSections(file_id,sections);

                //  Resource Analysis
                PEResourceAnalyzer resourceInfo =new PEResourceAnalyzer(fileBytes);
                analysisResults.put("resources", resourceInfo.getResources());
                resourceInfo.printResourceAnalysis();

                //Authenticode Signature Analysis
                PEAuthenticodeVerifier authenticodeVerifier = new PEAuthenticodeVerifier();
                authenticodeVerifier.analyze(fileBytes);
                PEAuthenticodeInfo peAuthenticodeInfo = authenticodeVerifier.getPeAuthenticodeInfo();
                analysisResults.put("authenticode_info", peAuthenticodeInfo);
                AuthenticodeInfoDao authenticodeInfoDao = new AuthenticodeInfoDao();
                authenticodeInfoDao.insertAuthenticodeInfo(file_id,peAuthenticodeInfo);

                //  Artifact Extraction
                PEArtifactExtractor artifacts = new PEArtifactExtractor(fileBytes);
                analysisResults.put("artifacts",artifacts.getStructuredArtifacts());

//                analysisResults.put("artifacts1", artifacts.getArtifacts());
//                PEArtifactExtractor artifacts2 = new PEArtifactExtractor(fileBytes,3);
//                analysisResults.put("artifacts2", artifacts2.getArtifacts());
//                PEArtifactExtractor artifacts3 = new PEArtifactExtractor(fileBytes,1);
//                analysisResults.put("artifacts3", artifacts3.getArtifacts());
                // Convert to JSON and send response
                String jsonResponse = objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(analysisResults);
                out.println(jsonResponse);
                System.out.println("Displaying through AnalysisResults");
                String allStrings = artifacts.extractAllStrings();
                analysisResults.put("extractedStrings", allStrings);
                jsonResponse = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(analysisResults);
                String folderPath = "C:\\Users\\yaswant-pt7919\\Malware Analysis\\Analysis Results";
                // Save to specific folder
                saveAsJsonFile(folderPath, analysisResults, fileName+".json");
                fileInfoDao.updateJsonFilePath(file_id,folderPath+"/"+fileName+".json");

            }
            else {
                String filePath = fileInfoDao.getJsonFilePath(peFileInfo.getSha1Hash());
                if (filePath == null || filePath.isEmpty()) {
                    throw new IOException("File path is null or empty");
                }

                try (FileInputStream fis = new FileInputStream(filePath)) {
                    String jsonResponse = new String(fis.readAllBytes(), StandardCharsets.UTF_8);
                    out.println(jsonResponse);
                    System.out.println("Displaying through file path");
                } catch (IOException e) {
                    System.err.println("Error reading JSON file: " + e.getMessage());
                    throw e; // Re-throw or handle appropriately
                }
            }
        } catch (Exception e) {
            sendError(response, out, "Analysis failed: " + e.getMessage(),
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
    public static void saveAsJsonFile(String folderPath , Object data, String filename) throws IOException {

        Path directory = Paths.get(folderPath);

        // Create directory if it doesn't exist
        if (!Files.exists(directory)) {
            Files.createDirectories(directory);
        }

        Path filePath = directory.resolve(filename);

        // Convert object to pretty JSON string
        String json = objectMapper.writerWithDefaultPrettyPrinter()
                .writeValueAsString(data);

        // Write to file
        Files.write(filePath, json.getBytes());
    }

    private void sendError(HttpServletResponse response, PrintWriter out,
                           String message, int statusCode) {
        response.setStatus(statusCode);
        try {
            Map<String, String> error = new LinkedHashMap<>();
            error.put("error", message);
            out.println(objectMapper.writeValueAsString(error));
        } catch (Exception e) {
            out.println("{\"error\": \"Failed to generate error message\"}");
        }
    }
}
