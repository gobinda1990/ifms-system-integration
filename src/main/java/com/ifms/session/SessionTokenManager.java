package com.ifms.session;

import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SessionTokenManager {

    private final Map<String, SessionToken> tokenCache = new ConcurrentHashMap<>();

    public void storeToken(String userId, String authToken, String sek, int expiryMins) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiresAt = now.plusMinutes(expiryMins);
        SessionToken token = new SessionToken(authToken, sek, expiresAt, now);
        tokenCache.put(userId, token);
    }

    public SessionToken getToken(String userId) {
        SessionToken token = tokenCache.get(userId);
        if (token != null && token.isValid()) {
            return token;
        }
        if (token != null) {
            tokenCache.remove(userId);
        }
        return null;
    }

    public boolean hasValidToken(String userId) {
        return getToken(userId) != null;
    }

    public void removeToken(String userId) {
        tokenCache.remove(userId);
    }

    public void cleanupExpiredTokens() {
        tokenCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }

    public String getSEK(String userId) {
        SessionToken token = getToken(userId);
        return token != null ? token.getSek() : null;
    }

    public String getAuthToken(String userId) {
        SessionToken token = getToken(userId);
        return token != null ? token.getAuthToken() : null;
    }
}