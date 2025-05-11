package DAO;

import Bean.DataDirectory;
import Utilities.DatabaseConnection;

import java.sql.*;
import javax.sql.DataSource;
import java.util.List;

public class DataDirectoriesDao {


    /**
     * Inserts a single DataDirectory into the database
     * @param fileId The foreign key reference to PE_File_Info
     * @param directory The DataDirectory object to insert
     * @return The generated directory_id
     * @throws SQLException
     */
    public int insertDataDirectory(int fileId, DataDirectory directory) throws SQLException {
        String sql = "INSERT INTO Data_Directories (" +
                "file_id, directory_index, name, virtual_address, size, section) " +
                "VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            stmt.setInt(1, fileId);
            stmt.setInt(2, directory.getIndex());
            stmt.setString(3, directory.getName());
            stmt.setInt(4, directory.getVirtualAddress());
            stmt.setInt(5, directory.getSize());
            stmt.setString(6, directory.getSection());

            int affectedRows = stmt.executeUpdate();

            if (affectedRows == 0) {
                throw new SQLException("Creating data directory failed, no rows affected.");
            }

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    return generatedKeys.getInt(1); // Return the generated directory_id
                } else {
                    throw new SQLException("Creating data directory failed, no ID obtained.");
                }
            }
        }
    }

    /**
     * Inserts multiple DataDirectories in a batch operation
     * @param fileId The foreign key reference to PE_File_Info
     * @param directories List of DataDirectory objects to insert
     * @return Number of directories inserted
     * @throws SQLException
     */
    public int insertDataDirectories(int fileId, List<DataDirectory> directories) throws SQLException {
        String sql = "INSERT INTO Data_Directories (" +
                "file_id, directory_index, name, virtual_address, size, section) " +
                "VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            for (DataDirectory directory : directories) {
                stmt.setInt(1, fileId);
                stmt.setInt(2, directory.getIndex());
                stmt.setString(3, directory.getName());
                stmt.setInt(4, directory.getVirtualAddress());
                stmt.setInt(5, directory.getSize());
                stmt.setString(6, directory.getSection());
                stmt.addBatch();
            }

            int[] results = stmt.executeBatch();
            return results.length;
        }
    }
}