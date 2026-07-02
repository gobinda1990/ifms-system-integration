# IFMS System Integration

Spring Boot 3.5 application for integrating with the IFMS (Integrated Food Management System) API using RSA and AES encryption.

## Overview

This application implements secure authentication and communication with the IFMS System. It handles:

- **RSA Encryption (2048-bit)**: Encrypts the AES symmetric key (appKey) using IFMS's RSA public key
- **AES Encryption (256-bit ECB mode)**: Encrypts/decrypts request and response payloads using the Session Encryption Key (SEK)
- **Session Management**: Manages authentication tokens and SEK with 30-minute expiry
- **Spring Security Integration**: Custom authentication provider for IFMS

## Key Components

### 1. EncryptionService
Handles all encryption and decryption operations:
- `generateAppKey()`: Creates a random 256-bit AES key
- `encryptAppKeyWithRSA()`: Encrypts appKey with IFMS RSA public key
- `encryptWithAES()`: Encrypts data using AES-256 ECB mode
- `decryptWithAES()`: Decrypts data using AES-256 ECB mode

### 2. IFMSAuthenticationService
Manages the complete authentication flow:
1. Generates random appKey (256-bit AES key)
2. Encrypts appKey with IFMS RSA public key
3. Encrypts clientSecret with appKey
4. Sends authentication request to IFMS
5. Receives authToken and encrypted SEK
6. Decrypts SEK using appKey
7. Stores token and SEK in SessionTokenManager

### 3. SessionTokenManager
Thread-safe token storage with:
- Token caching in ConcurrentHashMap
- Automatic expiry checking
- SEK and authToken retrieval
- Token cleanup for expired entries

### 4. AuthenticationController
REST endpoints:
- `POST /api/auth/login`: Authenticate user
- `POST /api/auth/refresh`: Refresh expired token
- `GET /api/auth/validate`: Validate token status

### 5. IFMSAPIClient
Generic client for making encrypted API calls to IFMS:
- Automatic encryption of requests
- Automatic decryption of responses
- Token management and header injection

## Configuration

Update `src/main/resources/application.yml`:

```yaml
ifms:
  api:
    base-url: http://domain-name/food/main/version
    authenticate-endpoint: /authenticate
    client-id: YOUR_CLIENT_ID
    client-secret: YOUR_CLIENT_SECRET
    rsa-public-key: |
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
      -----END PUBLIC KEY-----
  
  session:
    token-expiry-minutes: 30
    cache-enabled: true
```

## API Endpoints

### Login
```bash
POST /api/auth/login?userId=user123

Response:
{
  "status": "SUCCESS",
  "authToken": "uuid-token-value",
  "sek": "decrypted-session-encryption-key",
  "message": "Authentication successful"
}
```

### Refresh Token
```bash
POST /api/auth/refresh?userId=user123
```

### Validate Token
```bash
GET /api/auth/validate?userId=user123
```

## Building and Running

### Prerequisites
- Java 17+
- Maven 3.8+

### Build
```bash
mvn clean package
```

### Run
```bash
mvn spring-boot:run
```

Application will start at `http://localhost:8080/api`

## Testing

```bash
mvn test
```

## Security Features

1. **RSA-2048 Encryption**: AppKey is encrypted using IFMS's RSA public key
2. **AES-256 ECB Mode**: All request/response payloads are encrypted
3. **PKCS5 Padding**: Proper padding for block cipher encryption
4. **Token Expiry**: Automatic token expiration after 30 minutes
5. **Spring Security**: Integration with Spring Security for authentication