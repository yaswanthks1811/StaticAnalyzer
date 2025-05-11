package DAO;

import Bean.PEFileInfo;
import Utilities.DatabaseConnection;
import Utilities.Version;

import java.sql.*;
import javax.sql.DataSource;
import java.io.Serializable;

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

    public boolean isSha1Present(String SHA_1) throws SQLException{
        String sql = "SELECT sha1_hash FROM files WHERE sha1_hash = ?";
        try(Connection conn = DatabaseConnection.getConnection();
        PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1,SHA_1);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return true;

            }
        }
        return false;
    }

    public boolean updateJsonFilePath(int fileId, String filePath) throws SQLException {
        String sql = "UPDATE files SET json_file_path = ? WHERE file_id = ?";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, filePath);
            stmt.setInt(2, fileId);

            int affectedRows = stmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating file path failed, no rows affected.");
            }
            return true;
        }
    }

    public String getJsonFilePath(String sha1Hash) throws SQLException {
        String sql = "SELECT json_file_path FROM files WHERE sha1_hash = ?";
        try(Connection conn = DatabaseConnection.getConnection();
        PreparedStatement stmt = conn.prepareStatement(sql)){
            stmt.setString(1,sha1Hash);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getString("json_file_path");
            }
        }
        return null;
    }
}