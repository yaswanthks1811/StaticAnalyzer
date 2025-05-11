package Utilities;

public class Version {
    private static int version = 1;
    public static int getAnalyzerVersion(){
        return version;
    }
    public static void setAnalyzerVersion(int newVersion){
        version = newVersion;
    }
}
