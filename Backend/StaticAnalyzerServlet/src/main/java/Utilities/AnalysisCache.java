package Utilities;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.concurrent.TimeUnit;

public class AnalysisCache {

    private static final Cache<String, JsonNode> cache = Caffeine.newBuilder()
            .maximumSize(100)
            .expireAfterAccess(60, TimeUnit.MINUTES)
            .build();

    public static JsonNode get(String sha1) {
        return cache.getIfPresent(sha1);
    }

    public static void put(String sha1, JsonNode node) {
        cache.put(sha1, node);
    }

    public static boolean contains(String sha1) {
        return cache.getIfPresent(sha1) != null;
    }

    public static int getVersion(String sha1Hash) {
        return cache.getIfPresent(sha1Hash).get("analyzerVersion").asInt();
    }
}
