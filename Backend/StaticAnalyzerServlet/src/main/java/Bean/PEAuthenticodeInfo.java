package Bean;


import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

public class PEAuthenticodeInfo implements Serializable {


    private boolean hasSignature;
    private boolean valid;
    private String validationError;
    private X509Certificate certificate;
    private List<X509Certificate> certificateChain;
    private String sha1Thumbprint;
    private String sha256Thumbprint;
    private String version;
    private String serialNumber;
    private String issuerDN;
    private String notBefore;
    private String notAfter;
    private String subjectDN;
    private String publicKey;


    public PEAuthenticodeInfo() {
        // No-arg constructor
    }

    public boolean isHasSignature() {
        return hasSignature;
    }

    public void setHasSignature(boolean hasSignature) {
        this.hasSignature = hasSignature;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getValidationError() {
        return validationError;
    }

    public void setValidationError(String validationError) {
        this.validationError = validationError;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
        setIssuerDN(certificate.getIssuerDN().toString());
        setNotBefore(certificate.getNotBefore().toString());
        setNotAfter(certificate.getNotAfter().toString());
        setSubjectDN(certificate.getSubjectDN().toString());
        setPublicKey(certificate.getPublicKey().toString());
        setSerialNumber(certificate.getSerialNumber().toString());
        setVersion(String.valueOf(certificate.getVersion()));
        setPublicKey(certificate.getPublicKey().toString());
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(List<X509Certificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    public String getSha1Thumbprint() {
        return sha1Thumbprint;
    }

    public void setSha1Thumbprint(String sha1Thumbprint) {
        this.sha1Thumbprint = sha1Thumbprint;
    }

    public String getSha256Thumbprint() {
        return sha256Thumbprint;
    }

    public void setSha256Thumbprint(String sha256Thumbprint) {
        this.sha256Thumbprint = sha256Thumbprint;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
