package com.ifms.encryption;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

/**
 * Service for RSA and AES encryption/decryption operations
 */
@Service
public class EncryptionService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String KEY_ALGORITHM = "RSA";
    private static final int AES_KEY_SIZE = 256;

    public String generateAppKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE);
            SecretKey secretKey = keyGen.generateKey();
            return Base64.encodeBase64String(secretKey.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Error generating app key", e);
        }
    }

    public String encryptAppKeyWithRSA(String appKey, String rsaPublicKeyPem) {
        try {
            byte[] appKeyBytes = Base64.decodeBase64(appKey);
            PublicKey publicKey = loadPublicKeyFromPem(rsaPublicKeyPem);

            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedAppKey = cipher.doFinal(appKeyBytes);

            return Base64.encodeBase64String(encryptedAppKey);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting app key with RSA", e);
        }
    }

    public String encryptWithAES(String plainText, String aesKey) {
        try {
            byte[] decodedKey = Base64.decodeBase64(aesKey);
            SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            return Base64.encodeBase64String(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting with AES", e);
        }
    }

    public String decryptWithAES(String encryptedText, String aesKey) {
        try {
            byte[] decodedKey = Base64.decodeBase64(aesKey);
            SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decodedEncryptedText = Base64.decodeBase64(encryptedText);
            byte[] decryptedData = cipher.doFinal(decodedEncryptedText);

            return new String(decryptedData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting with AES", e);
        }
    }

    private PublicKey loadPublicKeyFromPem(String publicKeyPem) {
        try {
            String key = publicKeyPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] decodedKey = Base64.decodeBase64(key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Error loading public key from PEM", e);
        }
    }
}