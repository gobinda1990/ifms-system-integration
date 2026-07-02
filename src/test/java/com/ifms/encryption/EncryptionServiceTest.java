package com.ifms.encryption;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptionServiceTest {

    private EncryptionService encryptionService;

    @BeforeEach
    public void setUp() {
        encryptionService = new EncryptionService();
    }

    @Test
    public void testGenerateAppKey() {
        String appKey = encryptionService.generateAppKey();
        
        assertNotNull(appKey);
        assertFalse(appKey.isEmpty());
        assertTrue(appKey.length() > 0);
    }

    @Test
    public void testAESEncryptionDecryption() {
        String aesKey = encryptionService.generateAppKey();
        String plainText = "Hello, IFMS System!";

        String encrypted = encryptionService.encryptWithAES(plainText, aesKey);
        assertNotNull(encrypted);
        assertNotEquals(plainText, encrypted);

        String decrypted = encryptionService.decryptWithAES(encrypted, aesKey);
        assertEquals(plainText, decrypted);
    }

    @Test
    public void testAESEncryptionWithDifferentKey() {
        String aesKey1 = encryptionService.generateAppKey();
        String aesKey2 = encryptionService.generateAppKey();
        String plainText = "Test data";

        String encrypted = encryptionService.encryptWithAES(plainText, aesKey1);
        
        assertThrows(Exception.class, () -> {
            encryptionService.decryptWithAES(encrypted, aesKey2);
        });
    }
}