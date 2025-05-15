package Bean;

import java.io.Serializable;
import java.util.List;

public class PEArtifacts implements Serializable {
    private String section; // "all" or specific section name
    private List<String> artifactTypes; // ["urls", "filePaths", etc.]
    private int page;
    private int limit;
    private String searchTerm; // optional text search filter

    // Getters and setters
    public String getSection() { return section; }
    public void setSection(String section) { this.section = section; }
    public List<String> getArtifactTypes() { return artifactTypes; }
    public void setArtifactTypes(List<String> artifactTypes) { this.artifactTypes = artifactTypes; }
    public int getPage() { return page; }
    public void setPage(int page) { this.page = page; }
    public int getLimit() { return limit; }
    public void setLimit(int limit) { this.limit = limit; }
    public String getSearchTerm() { return searchTerm; }
    public void setSearchTerm(String searchTerm) { this.searchTerm = searchTerm; }
}