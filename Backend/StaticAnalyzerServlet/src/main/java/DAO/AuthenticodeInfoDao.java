package DAO;

import Bean.PEAuthenticodeInfo;
import Utilities.DatabaseConnection;

import java.sql.*;
import javax.sql.DataSource;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class AuthenticodeInfoDao {

    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    /**
     * Inserts Authenticode information into the database
     * @param fileId The foreign key reference to Files table
     * @param authInfo The PEAuthenticodeInfo object to insert
     * @return The generated auth_id
     * @throws SQLException
     */
    public int insertAuthenticodeInfo(int fileId, PEAuthenticodeInfo authInfo) throws SQLException {
        String sql = "INSERT INTO Authenticode_Info (" +
                "file_id, has_signature, is_valid, validation_error, " +
                "sha1_thumbprint, sha256_thumbprint, certificate_version, " +
                "serial_number, issuer_dn, not_before, not_after, " +
                "subject_dn, public_key_algorithm) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            // Set basic fields
            stmt.setInt(1, fileId);
            stmt.setBoolean(2, authInfo.isHasSignature());
            stmt.setBoolean(3, authInfo.isValid());
            stmt.setString(4, authInfo.getValidationError());
            stmt.setString(5, authInfo.getSha1Thumbprint());
            stmt.setString(6, authInfo.getSha256Thumbprint());
            stmt.setString(7, authInfo.getVersion());
            stmt.setString(8, authInfo.getSerialNumber());
            stmt.setString(9, authInfo.getIssuerDN());

            // Handle certificate dates
            setTimestampOrNull(stmt, 10, authInfo.getNotBefore());
            setTimestampOrNull(stmt, 11, authInfo.getNotAfter());

            stmt.setString(12, authInfo.getSubjectDN());
            stmt.setString(13, authInfo.getPublicKey());

            int affectedRows = stmt.executeUpdate();

            if (affectedRows == 0) {
                throw new SQLException("Creating Authenticode info failed, no rows affected.");
            }

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    int authId = generatedKeys.getInt(1);
                    if (authInfo.getCertificateChain() != null && !authInfo.getCertificateChain().isEmpty()) {
                        insertCertificateChain(authId, authInfo.getCertificateChain());
                    }
                    return authId;
                } else {
                    throw new SQLException("Creating Authenticode info failed, no ID obtained.");
                }
            }
        }
    }

    /**
     * Helper method to handle timestamp conversion
     */
    private void setTimestampOrNull(PreparedStatement stmt, int parameterIndex, String dateString)
            throws SQLException {
        if (dateString != null && !dateString.isEmpty()) {
            try {
                Date date = dateFormat.parse(dateString);
                stmt.setTimestamp(parameterIndex, new Timestamp(date.getTime()));
            } catch (Exception e) {
                stmt.setNull(parameterIndex, Types.TIMESTAMP);
            }
        } else {
            stmt.setNull(parameterIndex, Types.TIMESTAMP);
        }
    }

    /**
     * Inserts the certificate chain into a separate table
     */
    private void insertCertificateChain(int authId, List<X509Certificate> certificateChain)
            throws SQLException {
        String sql = "INSERT INTO Certificate_Chain (" +
                "auth_id, cert_order, subject_dn, issuer_dn, " +
                "serial_number, not_before, not_after, " +
                "signature_algorithm, public_key_algorithm) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            int order = 0;
            for (X509Certificate cert : certificateChain) {
                stmt.setInt(1, authId);
                stmt.setInt(2, order++);
                stmt.setString(3, cert.getSubjectDN().toString());
                stmt.setString(4, cert.getIssuerDN().toString());
                stmt.setString(5, cert.getSerialNumber().toString());
                stmt.setTimestamp(6, new Timestamp(cert.getNotBefore().getTime()));
                stmt.setTimestamp(7, new Timestamp(cert.getNotAfter().getTime()));
                stmt.setString(8, cert.getSigAlgName());
                stmt.setString(9, cert.getPublicKey().getAlgorithm());
                stmt.addBatch();
            }
            stmt.executeBatch();
        }
    }
}
