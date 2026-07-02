package com.ifms.controller;

import com.ifms.dto.AuthenticationResponse;
import com.ifms.service.IFMSAuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

    private final IFMSAuthenticationService ifmsAuthenticationService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestParam(required = false) String userId) {
        try {
            if (userId == null || userId.isEmpty()) {
                userId = SecurityContextHolder.getContext()
                        .getAuthentication()
                        .getName();
            }

            log.info("Login request for user: {}", userId);

            AuthenticationResponse response = ifmsAuthenticationService.authenticate(userId);

            Map<String, Object> result = new HashMap<>();
            result.put("status", response.getStatus());
            result.put("authToken", response.getAuthToken());
            result.put("sek", response.getSek());
            result.put("message", "Authentication successful");

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("Login failed", e);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "FAILED");
            error.put("message", "Authentication failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(
            @RequestParam(required = false) String userId) {
        try {
            if (userId == null || userId.isEmpty()) {
                userId = SecurityContextHolder.getContext()
                        .getAuthentication()
                        .getName();
            }

            log.info("Token refresh request for user: {}", userId);

            AuthenticationResponse response = ifmsAuthenticationService.refreshToken(userId);

            Map<String, Object> result = new HashMap<>();
            result.put("status", response.getStatus());
            result.put("authToken", response.getAuthToken());
            result.put("sek", response.getSek());
            result.put("message", "Token refreshed successfully");

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("Token refresh failed", e);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "FAILED");
            error.put("message", "Token refresh failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(
            @RequestParam(required = false) String userId) {
        try {
            if (userId == null || userId.isEmpty()) {
                userId = SecurityContextHolder.getContext()
                        .getAuthentication()
                        .getName();
            }

            boolean isValid = ifmsAuthenticationService.hasValidToken(userId);

            Map<String, Object> result = new HashMap<>();
            result.put("userId", userId);
            result.put("hasValidToken", isValid);
            result.put("message", isValid ? "Token is valid" : "Token is invalid or expired");

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("Token validation failed", e);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "FAILED");
            error.put("message", "Validation failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }
}