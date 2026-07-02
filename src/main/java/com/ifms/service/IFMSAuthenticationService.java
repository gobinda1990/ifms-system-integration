package com.ifms.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ifms.config.IFMSConfig;
import com.ifms.dto.AuthenticationRequest;
import com.ifms.dto.AuthenticationResponse;
import com.ifms.encryption.EncryptionService;
import com.ifms.session.SessionTokenManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
@Slf4j
public class IFMSAuthenticationService {

    private final EncryptionService encryptionService;
    private final IFMSConfig ifmsConfig;
    private final SessionTokenManager sessionTokenManager;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public AuthenticationResponse authenticate(String userId) {
        try {
            log.info("Starting IFMS authentication for user: {}", userId);

            String appKey = encryptionService.generateAppKey();
            log.debug("Generated appKey");

            String encryptedAppKey = encryptionService.encryptAppKeyWithRSA(
                    appKey,
                    ifmsConfig.getApi().getRsaPublicKey()
            );
            log.debug("Encrypted appKey with RSA public key");

            String encryptedClientSecret = encryptionService.encryptWithAES(
                    ifmsConfig.getApi().getClientSecret(),
                    appKey
            );
            log.debug("Encrypted clientSecret with AES");

            AuthenticationRequest authRequest = new AuthenticationRequest(
                    ifmsConfig.getApi().getClientId(),
                    encryptedClientSecret,
                    encryptedAppKey
            );

            AuthenticationResponse authResponse = sendAuthenticationRequest(authRequest);
            log.info("Successfully authenticated with IFMS");

            String decryptedSEK = encryptionService.decryptWithAES(
                    authResponse.getSek(),
                    appKey
            );
            log.debug("Decrypted SEK using appKey");

            sessionTokenManager.storeToken(
                    userId,
                    authResponse.getAuthToken(),
                    decryptedSEK,
                    ifmsConfig.getSession().getTokenExpiryMinutes()
            );
            log.info("Stored session token for user: {}", userId);

            authResponse.setSek(decryptedSEK);
            return authResponse;

        } catch (Exception e) {
            log.error("IFMS authentication failed for user: {}", userId, e);
            throw new RuntimeException("Authentication failed", e);
        }
    }

    private AuthenticationResponse sendAuthenticationRequest(AuthenticationRequest authRequest) {
        try {
            String url = ifmsConfig.getApi().getBaseUrl() + ifmsConfig.getApi().getAuthenticateEndpoint();
            log.debug("Sending authentication request to: {}", url);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<AuthenticationRequest> entity = new HttpEntity<>(authRequest, headers);
            ResponseEntity<AuthenticationResponse> response = restTemplate.postForEntity(
                    url,
                    entity,
                    AuthenticationResponse.class
            );

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new RuntimeException("Invalid response from IFMS authentication API");
            }

            return response.getBody();

        } catch (Exception e) {
            log.error("Error sending authentication request to IFMS", e);
            throw new RuntimeException("Failed to send authentication request", e);
        }
    }

    public AuthenticationResponse refreshToken(String userId) {
        log.info("Refreshing token for user: {}", userId);
        sessionTokenManager.removeToken(userId);
        return authenticate(userId);
    }

    public boolean hasValidToken(String userId) {
        return sessionTokenManager.hasValidToken(userId);
    }

    public String getSEK(String userId) {
        return sessionTokenManager.getSEK(userId);
    }

    public String getAuthToken(String userId) {
        return sessionTokenManager.getAuthToken(userId);
    }
}