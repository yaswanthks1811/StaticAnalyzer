package DAO;
import Bean.PEFileInfo;
import Bean.PEStaticInfo;
import Utilities.DatabaseConnection;

import java.sql.*;
import javax.sql.DataSource;

public class PEStaticInfoDao {


    public int insertPEStaticInfo(int fileId, PEStaticInfo peFileInfo) throws SQLException {
        String sql = "INSERT INTO PE_File_Info (" +
                "file_id, entry_point, entry_point_section, digitally_signed, " +
                "image_base, subsystem, image_characteristics, dll_characteristics, " +
                "timestamp, tls_callbacks, clr_version, os_version_major, " +
                "os_version_minor, file_version_major, file_version_minor, " +
                "subsystem_version_major, subsystem_version_minor, rich_header_offset, " +
                "xorkey, import_hash) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            // Set parameters
            stmt.setInt(1, fileId);
            stmt.setLong(2, peFileInfo.getEntryPoint());
            stmt.setString(3, peFileInfo.getEntryPointSection());
            stmt.setBoolean(4, peFileInfo.isDigitallySigned());
            stmt.setLong(5, peFileInfo.getImageBase());
            stmt.setString(6, peFileInfo.getSubsystem());
            stmt.setString(7, peFileInfo.getImageFileCharacteristics());
            stmt.setString(8, peFileInfo.getDllCharacteristics());

            // Handle timestamp (convert from String to Timestamp if needed)
            if (peFileInfo.getTimeStamp() != null && !peFileInfo.getTimeStamp().isEmpty()) {
                try {
                    Timestamp timestamp = Timestamp.valueOf(peFileInfo.getTimeStamp());
                    stmt.setTimestamp(9, timestamp);
                } catch (IllegalArgumentException e) {
                    stmt.setNull(9, Types.TIMESTAMP);
                }
            } else {
                stmt.setNull(9, Types.TIMESTAMP);
            }

            stmt.setString(10, peFileInfo.getTlsCallbacks());
            stmt.setString(11, peFileInfo.getClrVersion());
            stmt.setInt(12, peFileInfo.getOsVersionMajor());
            stmt.setInt(13, peFileInfo.getOsVersionMinor());
            stmt.setInt(14, peFileInfo.getFileVersionMajor());
            stmt.setInt(15, peFileInfo.getFileVersionMinor());
            stmt.setInt(16, peFileInfo.getSubsystemVersionMajor());
            stmt.setInt(17, peFileInfo.getSubsystemVersionMinor());
            stmt.setInt(18, peFileInfo.getRichHeaderOffset());
            stmt.setString(19, peFileInfo.getXorkey());
            stmt.setString(20, peFileInfo.getImportHash());

            int affectedRows = stmt.executeUpdate();

            if (affectedRows == 0) {
                throw new SQLException("Creating PE file info failed, no rows affected.");
            }

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    return generatedKeys.getInt(1); // Return the generated pe_info_id
                } else {
                    throw new SQLException("Creating PE file info failed, no ID obtained.");
                }
            }
        }
    }
}