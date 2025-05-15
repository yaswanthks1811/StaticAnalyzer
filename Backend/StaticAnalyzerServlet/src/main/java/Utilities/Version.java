package Utilities;

public class Version {
    private static int version = 2;
    public static int getAnalyzerVersion(){
        return version;
    }
    public static void setAnalyzerVersion(int newVersion){
        version = newVersion;
    }
    public static boolean isAnalyzerVersion(int inputVersion){
        return version == inputVersion;
    }
}
