package DAO;
import Bean.PESection;
import Utilities.DatabaseConnection;

import java.sql.*;
import javax.sql.DataSource;
import java.util.List;

public class PESectionDao {


    /**
     * Inserts a single PE section into the database
     * @param fileId The foreign key reference to Files table
     * @param section The PESection object to insert
     * @return The generated section_id
     * @throws SQLException
     */
    public int insertSection(int fileId, PESection section) throws SQLException {
        String sql = "INSERT INTO Sections (" +
                "file_id, name, virtual_size, virtual_address, " +
                "raw_size, raw_offset, characteristics, md5, entropy, type) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            stmt.setInt(1, fileId);
            stmt.setString(2, section.name);
            stmt.setInt(3, section.virtualSize);
            stmt.setInt(4, section.virtualAddress);
            stmt.setInt(5, section.rawSize);
            stmt.setInt(6, section.rawOffset);
            stmt.setString(7, String.format("0x%08X", section.characteristics));
            stmt.setString(8, section.md5);
            stmt.setDouble(9, section.entropy);
            stmt.setString(10, section.type);

            int affectedRows = stmt.executeUpdate();

            if (affectedRows == 0) {
                throw new SQLException("Creating section failed, no rows affected.");
            }

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    return generatedKeys.getInt(1); // Return the generated section_id
                } else {
                    throw new SQLException("Creating section failed, no ID obtained.");
                }
            }
        }
    }

    /**
     * Inserts multiple PE sections in a batch operation
     * @param fileId The foreign key reference to Files table
     * @param sections List of PESection objects to insert
     * @return Number of sections inserted
     * @throws SQLException
     */
    public int insertSections(int fileId, List<PESection> sections) throws SQLException {
        String sql = "INSERT INTO Sections (" +
                "file_id, name, virtual_size, virtual_address, " +
                "raw_size, raw_offset, characteristics, md5, entropy, type) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            for (PESection section : sections) {
                stmt.setInt(1, fileId);
                stmt.setString(2, section.name);
                stmt.setInt(3, section.virtualSize);
                stmt.setInt(4, section.virtualAddress);
                stmt.setInt(5, section.rawSize);
                stmt.setInt(6, section.rawOffset);
                stmt.setString(7, String.format("0x%08X", section.characteristics));
                stmt.setString(8, section.md5);
                stmt.setDouble(9, section.entropy);
                stmt.setString(10, section.type);
                stmt.addBatch();
            }

            int[] results = stmt.executeBatch();
            return results.length;
        }
    }
}