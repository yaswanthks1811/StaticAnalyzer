package DAO;

import Bean.PEFileInfo;
import Utilities.DatabaseConnection;
import Utilities.Version;

import java.sql.*;
import javax.sql.DataSource;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class FileInfoDao {

    private final int analyzerVersion = Version.getAnalyzerVersion();



    public int insertFile(PEFileInfo fileInfo) throws SQLException {
        String sql = "INSERT INTO Files (filename, file_size, file_type, entropy, " +
                "md5_hash, sha1_hash, sha256_hash, sha512_hash, content_preview, analyzer_version) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            stmt.setString(1, fileInfo.getFileName());
            stmt.setLong(2, fileInfo.getFileSize());
            stmt.setString(3, fileInfo.getFileType());
            stmt.setDouble(4, fileInfo.getEntropy());
            stmt.setString(5, fileInfo.getMd5Hash());
            stmt.setString(6, fileInfo.getSha1Hash());
            stmt.setString(7, fileInfo.getSha256Hash());
            stmt.setString(8, fileInfo.getSha512Hash());
            stmt.setString(9, fileInfo.getContentPreview());
            stmt.setInt(10, analyzerVersion);

            int affectedRows = stmt.executeUpdate();

            if (affectedRows == 0) {
                throw new SQLException("Creating file failed, no rows affected.");
            }

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    return generatedKeys.getInt(1); // Return the generated file_id
                } else {
                    throw new SQLException("Creating file failed, no ID obtained.");
                }
            }
        }
    }

    public int getAnalyzerVersion(String SHA_1) throws SQLException{
        String sql = "SELECT analyzer_version FROM files WHERE sha1_hash = ?";
        try(Connection conn = DatabaseConnection.getConnection();
        PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1,SHA_1);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("analyzer_version");
            }
        }
        return -1;
    }

    public boolean isSha1Present(String SHA_1,int version) throws SQLException{
        String sql = "SELECT sha1_hash FROM files WHERE sha1_hash = ? and analyzer_version = ?";
        try(Connection conn = DatabaseConnection.getConnection();
        PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1,SHA_1);
            stmt.setInt(2,version);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return true;
            }
        }
        return false;
    }

    public String getJsonFilePath(String sha1Hash,int analyzerVersion) throws SQLException {
        String sql = "SELECT json_file_path FROM files WHERE sha1_hash = ? and analyzer_version = ?";
        try(Connection conn = DatabaseConnection.getConnection();
        PreparedStatement stmt = conn.prepareStatement(sql)){
            stmt.setString(1,sha1Hash);
            stmt.setInt(2,analyzerVersion);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getString("json_file_path");
            }
        }
        return null;
    }

    public String getArtifactsFilePath(String sha1Hash,int analyzerVersion) throws SQLException {
        String sql = "SELECT artifacts_file_path FROM files WHERE sha1_hash = ?  and analyzer_version = ?";
        try(Connection conn = DatabaseConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement(sql)){
            stmt.setString(1,sha1Hash);
            stmt.setInt(2,analyzerVersion);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getString("artifacts_file_path");
            }
        }
        return null;
    }

    public int getFileId(String sha1Hash) throws SQLException {
        String sql = "SELECT file_id FROM files WHERE sha1_hash = ?";
        try(Connection conn = DatabaseConnection.getConnection();
        PreparedStatement stmt = conn.prepareStatement(sql)){
            stmt.setString(1,sha1Hash);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("file_id");
            }
        }
        return -1;
    }

    public boolean updatePaths(int fileId, String filePath1, String filePath2) throws SQLException {
        String sql = "UPDATE files SET json_file_path =? ,artifacts_file_path = ? WHERE file_id = ?";
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1,filePath1 );
            stmt.setString(2, filePath2);
            stmt.setInt(3, fileId);

            int affectedRows = stmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating file path failed, no rows affected.");
            }
            return true;
        }
    }
    public List<Map<String, Object>> getFileSummaryList() throws SQLException {
        List<Map<String, Object>> files = new ArrayList<>();
        String sql = "SELECT file_id, filename, file_size, file_type, upload_date,entropy , sha1_hash, analyzer_version FROM Files ORDER BY upload_date DESC";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                Map<String, Object> fileInfo = new LinkedHashMap<>();
                fileInfo.put("id", rs.getInt("file_id"));
                fileInfo.put("name", rs.getString("filename"));
                fileInfo.put("size", formatFileSize(rs.getInt("file_size")));
                fileInfo.put("type", rs.getString("file_type"));
                fileInfo.put("date", rs.getTimestamp("upload_date"));
                fileInfo.put("hash", rs.getString("sha1_hash"));
                fileInfo.put("version", rs.getInt("analyzer_version"));
                fileInfo.put("entropy", rs.getDouble("entropy"));
                files.add(fileInfo);
            }
        }
        return files;
    }

    private String formatFileSize(long size) {
        if (size < 1024) return size + " B";
        int exp = (int) (Math.log(size) / Math.log(1024));
        String pre = "KMGTPE".charAt(exp-1) + "i";
        return String.format("%.1f %sB", size / Math.pow(1024, exp), pre);
    }
}