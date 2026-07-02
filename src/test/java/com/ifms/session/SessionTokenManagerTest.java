package com.ifms.session;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

public class SessionTokenManagerTest {

    private SessionTokenManager sessionTokenManager;

    @BeforeEach
    public void setUp() {
        sessionTokenManager = new SessionTokenManager();
    }

    @Test
    public void testStoreAndRetrieveToken() {
        String userId = "user123";
        String authToken = "auth-token-xyz";
        String sek = "session-encryption-key-abc";
        int expiryMins = 30;

        sessionTokenManager.storeToken(userId, authToken, sek, expiryMins);
        SessionToken token = sessionTokenManager.getToken(userId);

        assertNotNull(token);
        assertEquals(authToken, token.getAuthToken());
        assertEquals(sek, token.getSek());
        assertTrue(token.isValid());
    }

    @Test
    public void testHasValidToken() {
        String userId = "user123";

        assertFalse(sessionTokenManager.hasValidToken(userId));

        sessionTokenManager.storeToken(userId, "auth-token", "sek", 30);

        assertTrue(sessionTokenManager.hasValidToken(userId));
    }

    @Test
    public void testRemoveToken() {
        String userId = "user123";
        sessionTokenManager.storeToken(userId, "auth-token", "sek", 30);

        assertTrue(sessionTokenManager.hasValidToken(userId));

        sessionTokenManager.removeToken(userId);

        assertFalse(sessionTokenManager.hasValidToken(userId));
    }

    @Test
    public void testGetSEK() {
        String userId = "user123";
        String sek = "my-secret-encryption-key";

        sessionTokenManager.storeToken(userId, "auth-token", sek, 30);
        String retrievedSek = sessionTokenManager.getSEK(userId);

        assertEquals(sek, retrievedSek);
    }

    @Test
    public void testGetAuthToken() {
        String userId = "user123";
        String authToken = "my-auth-token";

        sessionTokenManager.storeToken(userId, authToken, "sek", 30);
        String retrievedToken = sessionTokenManager.getAuthToken(userId);

        assertEquals(authToken, retrievedToken);
    }

    @Test
    public void testExpiredToken() {
        LocalDateTime now = LocalDateTime.now();
        SessionToken expiredToken = new SessionToken("token", "sek", now.minusMinutes(1), now);

        assertFalse(expiredToken.isValid());
        assertTrue(expiredToken.isExpired());
    }

    @Test
    public void testMultipleUsers() {
        sessionTokenManager.storeToken("user1", "token1", "sek1", 30);
        sessionTokenManager.storeToken("user2", "token2", "sek2", 30);

        assertEquals("token1", sessionTokenManager.getAuthToken("user1"));
        assertEquals("token2", sessionTokenManager.getAuthToken("user2"));
        assertEquals("sek1", sessionTokenManager.getSEK("user1"));
        assertEquals("sek2", sessionTokenManager.getSEK("user2"));
    }
}