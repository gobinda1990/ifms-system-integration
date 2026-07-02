package com.ifms.service;

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
public class IFMSAPIClient {

    private final RestTemplate restTemplate;
    private final EncryptionService encryptionService;
    private final SessionTokenManager sessionTokenManager;

    public String makeAPICall(String userId, String url, String requestBody, String method) {
        try {
            String sek = sessionTokenManager.getSEK(userId);
            String authToken = sessionTokenManager.getAuthToken(userId);

            if (sek == null || authToken == null) {
                throw new RuntimeException("No valid session token for user: " + userId);
            }

            log.debug("Making IFMS API call for user: {} to URL: {}", userId, url);

            String encryptedRequest = encryptionService.encryptWithAES(requestBody, sek);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("Authorization", "Bearer " + authToken);
            headers.set("X-Encrypted", "true");

            HttpEntity<String> entity = new HttpEntity<>(encryptedRequest, headers);
            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("IFMS API call failed with status: " + response.getStatusCode());
            }

            String decryptedResponse = encryptionService.decryptWithAES(response.getBody(), sek);
            log.debug("Successfully received and decrypted response from IFMS");

            return decryptedResponse;

        } catch (Exception e) {
            log.error("Error making IFMS API call", e);
            throw new RuntimeException("IFMS API call failed", e);
        }
    }

    public String get(String userId, String url) {
        return makeAPICall(userId, url, "", "GET");
    }

    public String post(String userId, String url, String requestBody) {
        return makeAPICall(userId, url, requestBody, "POST");
    }

    public String put(String userId, String url, String requestBody) {
        return makeAPICall(userId, url, requestBody, "PUT");
    }

    public String delete(String userId, String url) {
        return makeAPICall(userId, url, "", "DELETE");
    }
}