package com.ifms.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "ifms")
@Data
public class IFMSConfig {
    private ApiConfig api;
    private SessionConfig session;

    @Data
    public static class ApiConfig {
        private String baseUrl;
        private String authenticateEndpoint;
        private String clientId;
        private String clientSecret;
        private String rsaPublicKey;
    }

    @Data
    public static class SessionConfig {
        private int tokenExpiryMinutes;
        private boolean cacheEnabled;
    }
}