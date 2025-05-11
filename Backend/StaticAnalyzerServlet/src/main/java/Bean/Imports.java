package Bean;


import java.io.Serializable;
import java.util.List;

public class Imports implements Serializable {
    private String dllName;
    private List<String> functionNames;

    public Imports() {
    }

    public Imports(String dllName, List<String> functionNames) {
        this.dllName = dllName;
        this.functionNames = functionNames;
    }

    public String getDllName() {
        return dllName;
    }

    public void setDllName(String dllName) {
        this.dllName = dllName;
    }

    public List<String> getFunctionName() {
        return functionNames;
    }

    public void setFunctionName(List<String> functionName) {
        this.functionNames = functionName;
    }

    @Override
    public String toString() {
        return "PEImport{" +
                "dllName='" + dllName + '\'' +
                ", functionName='" + functionNames + '\'' +
                '}';
    }
}
