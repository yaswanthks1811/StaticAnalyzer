package Bean;


import java.util.Set;

public class PEArtifacts {

    private Set<String> urls;
    private Set<String> filePaths;
    private Set<String> ipAddresses;
    private Set<String> emailAddresses;
    private Set<String> interestingStrings;
    private Set<String> registryKeys;
    private Set<String> domains;
    private Set<String> apiCalls;
    private Set<String> metadata;

    public PEArtifacts() {
        // No-arg constructor
    }

    public Set<String> getUrls() {
        return urls;
    }

    public void setUrls(Set<String> urls) {
        this.urls = urls;
    }

    public Set<String> getFilePaths() {
        return filePaths;
    }

    public void setFilePaths(Set<String> filePaths) {
        this.filePaths = filePaths;
    }

    public Set<String> getIpAddresses() {
        return ipAddresses;
    }

    public void setIpAddresses(Set<String> ipAddresses) {
        this.ipAddresses = ipAddresses;
    }

    public Set<String> getEmailAddresses() {
        return emailAddresses;
    }

    public void setEmailAddresses(Set<String> emailAddresses) {
        this.emailAddresses = emailAddresses;
    }

    public Set<String> getInterestingStrings() {
        return interestingStrings;
    }

    public void setInterestingStrings(Set<String> interestingStrings) {
        this.interestingStrings = interestingStrings;
    }

    public void setRegistryKeys(Set<String> registryKeys) {
        this.registryKeys = registryKeys;
    }

    public Set<String> getRegistryKeys() {
        return registryKeys;
    }

    public void setDomains(Set<String> domains) {
        this.domains = domains;
    }

    public Set<String> getDomains() {
        return domains;
    }

    public void setApiCalls(Set<String> apiCalls) {
        this.apiCalls = apiCalls;
    }

    public Set<String> getApiCalls() {
        return apiCalls;
    }

    public void setMetadata(Set<String> metadata) {
        this.metadata = metadata;
    }

    public Set<String> getMetadata() {
        return metadata;
    }
}
