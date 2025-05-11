package Analyzers;

import Bean.PEAuthenticodeInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

public class PEAuthenticodeVerifier{

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private X509Certificate certificate;
    private boolean isValid;
    private boolean hasSignature;
    private String validationError = "No signature found";
    private List<X509Certificate> certificateChain = new ArrayList<>();
    private PEAuthenticodeInfo peAuthenticodeInfo;

    public PEAuthenticodeVerifier() {
    }

    public void analyze(byte[] fileBytes) {
        resetState();

        try {
            if (fileBytes == null || fileBytes.length < 64) {
                this.validationError = "File is too small or null";
                return;
            }

            byte[] signatureData = extractSignatureData(fileBytes);
            if (signatureData == null || signatureData.length == 0) {
                this.hasSignature = false;
                this.validationError = "No Authenticode signature found";
                return;
            }

            this.hasSignature = true;
            processSignatureData(signatureData);

        } catch (Exception e) {
            this.validationError = "Analysis error: " + e.getMessage();
        }
    }

    private void resetState() {
        this.certificate = null;
        this.isValid = false;
        this.hasSignature = false;
        this.certificateChain.clear();
        this.validationError = "No signature found";
    }

    private byte[] extractSignatureData(byte[] fileBytes) throws IOException {
        if (fileBytes[0] != 'M' || fileBytes[1] != 'Z') {
            return null;
        }

        int peOffset = ByteBuffer.wrap(fileBytes, 0x3C, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (peOffset <= 0 || peOffset >= fileBytes.length) {
            return null;
        }

        if (fileBytes[peOffset] != 'P' || fileBytes[peOffset + 1] != 'E') {
            return null;
        }

        int optionalHeaderOffset = peOffset + 24;
        int magic = ByteBuffer.wrap(fileBytes, optionalHeaderOffset, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;

        boolean is64bit = (magic == 0x20b);

        int dataDirOffset = optionalHeaderOffset + (is64bit ? 112 : 96);
        int certTableRva = ByteBuffer.wrap(fileBytes, dataDirOffset + 8 * 4, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
        int certTableSize = ByteBuffer.wrap(fileBytes, dataDirOffset + 8 * 4 + 4, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (certTableSize == 0 || certTableRva == 0) {
            return null;
        }

        int certTableOffset = certTableRva;
        if (certTableOffset <= 0 || certTableOffset + certTableSize > fileBytes.length) {
            return null;
        }

        int certLength = ByteBuffer.wrap(fileBytes, certTableOffset, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
        int revision = ByteBuffer.wrap(fileBytes, certTableOffset + 4, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        int certType = ByteBuffer.wrap(fileBytes, certTableOffset + 6, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;

        if (certType != 2) { // WIN_CERT_TYPE_PKCS_SIGNED_DATA
            return null;
        }

        if (certLength <= 8 || certTableOffset + certLength > fileBytes.length) {
            return null;
        }

        byte[] signatureData = new byte[certLength - 8];
        System.arraycopy(fileBytes, certTableOffset + 8, signatureData, 0, signatureData.length);
        return signatureData;
    }

    private void processSignatureData(byte[] signatureData) throws Exception {
        CMSSignedData signedData = new CMSSignedData(signatureData);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                .setProvider("BC");

        Collection<X509CertificateHolder> certHolders = signedData.getCertificates().getMatches(null);
        if (certHolders.isEmpty()) {
            this.validationError = "No certificates found in signature";
            return;
        }

        for (X509CertificateHolder holder : certHolders) {
            certificateChain.add(converter.getCertificate(holder));
        }

        this.certificate = certificateChain.get(0);
        this.isValid = verifyCertificate();
    }

    private boolean verifyCertificate() {
        try {
            this.certificate.checkValidity();
            this.validationError = "Valid signature";
            return true;
        } catch (CertificateExpiredException e) {
            this.validationError = "Certificate expired";
        } catch (CertificateNotYetValidException e) {
            this.validationError = "Certificate not yet valid";
        } catch (Exception e) {
            this.validationError = "Certificate validation failed: " + e.getMessage();
        }
        return false;
    }

    // Getters
    public boolean hasSignature() {
        return hasSignature;
    }

    public boolean isValid() {
        return isValid;
    }

    public String getValidationError() {
        return validationError;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public String getThumbprint(String algorithm) throws Exception {
        if (certificate == null)
            return "";
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digest = md.digest(certificate.getEncoded());
        return bytesToHex(digest);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public void printCertificateDetails() {
        if (certificate == null) {
            System.out.println("No certificate available");
            return;
        }
        System.out.println("Version: " + certificate.getVersion());
        System.out.println("SerialNumber: " + certificate.getSerialNumber());
        System.out.println("IssuerDN: " + certificate.getIssuerDN());
        System.out.println("Start Date: " + certificate.getNotBefore());
        System.out.println("Final Date: " + certificate.getNotAfter());
        System.out.println("SubjectDN: " + certificate.getSubjectDN());
        System.out.println("Public Key: " + certificate.getPublicKey().getAlgorithm());
        try {
            System.out.println("SHA1 Thumbprint: " + getThumbprint("SHA-1"));
            System.out.println("SHA256 Thumbprint: " + getThumbprint("SHA-256"));
        } catch (Exception e) {
            System.err.println("Error generating thumbprints: " + e.getMessage());
        }
    }

    public PEAuthenticodeInfo getPeAuthenticodeInfo() throws Exception {
        peAuthenticodeInfo = new PEAuthenticodeInfo();
        peAuthenticodeInfo.setHasSignature(hasSignature);
        peAuthenticodeInfo.setValid(isValid);
        peAuthenticodeInfo.setValidationError(getValidationError());

        // Convert certificate chain to Base64 strings
        List<String> certChainBase64 = new ArrayList<>();
        if (certificateChain != null) {
            for (X509Certificate cert : certificateChain) {
                certChainBase64.add(Base64.getEncoder().encodeToString(cert.getEncoded()));
            }
        }


        // Add certificate details
        if (certificate != null) {
            peAuthenticodeInfo.setIssuerDN(certificate.getIssuerDN().toString());
            peAuthenticodeInfo.setSubjectDN(certificate.getSubjectDN().toString());
            peAuthenticodeInfo.setNotBefore(String.valueOf(certificate.getNotBefore()));
            peAuthenticodeInfo.setNotAfter(String.valueOf(certificate.getNotAfter()));
            peAuthenticodeInfo.setSerialNumber(certificate.getSerialNumber().toString());
            peAuthenticodeInfo.setPublicKey(certificate.getPublicKey().getAlgorithm());
        }

        peAuthenticodeInfo.setSha1Thumbprint(getThumbprint("SHA-1"));
        peAuthenticodeInfo.setSha256Thumbprint(getThumbprint("SHA-256"));

        return peAuthenticodeInfo;
    }
}