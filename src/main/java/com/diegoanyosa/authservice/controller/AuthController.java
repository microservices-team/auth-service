package com.diegoanyosa.authservice.controller;

import com.diegoanyosa.authservice.AuthApiDelegate;
import com.diegoanyosa.authservice.model.*;
import com.diegoanyosa.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Implements the generated {@link AuthApiDelegate}.
 *
 * ## Auth resolution strategy
 *
 * Protected endpoints receive xUserId as a nullable UUID because the YAML
 * declares X-User-Id as required=false. This supports two calling modes:
 *
 *   1. Direct call (Postman / Swagger UI):
 *      Send "Authorization: Bearer <accessToken>" or "X-API-Key: <rawKey>".
 *      JwtAuthFilter / ApiKeyAuthFilter sets the Authentication principal.
 *      xUserId will be null — resolveUserId() falls back to auth.getName().
 *
 *   2. Behind the API Gateway (production):
 *      The gateway validates the JWT and injects X-User-Id as a header.
 *      xUserId will be populated — we use it directly.
 */
@Component
@RequiredArgsConstructor
public class AuthController implements AuthApiDelegate {

    private final AuthService authService;

    // ── Public endpoints ──────────────────────────────────────────────────

    @Override
    public ResponseEntity<AuthApiResponse> login(LoginRequest request) {
        AuthApiResponse body = new AuthApiResponse();
        body.setSuccess(true);
        body.setMessage("Login successful");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(authService.login(request));
        return ResponseEntity.ok(body);
    }

    @Override
    public ResponseEntity<AuthApiResponse> register(RegisterRequest request) {
        AuthApiResponse body = new AuthApiResponse();
        body.setSuccess(true);
        body.setMessage("Registered");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(authService.register(request));
        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    @Override
    public ResponseEntity<AuthApiResponse> refreshToken(RefreshTokenRequest request) {
        AuthApiResponse body = new AuthApiResponse();
        body.setSuccess(true);
        body.setMessage("Token refreshed");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(authService.refresh(request));
        return ResponseEntity.ok(body);
    }

    @Override
    public ResponseEntity<ProvidersApiResponse> getOAuth2Providers() {
        ProvidersApiResponse body = new ProvidersApiResponse();
        body.setSuccess(true);
        body.setMessage("Available providers");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(List.of("google", "github"));
        return ResponseEntity.ok(body);
    }

    // ── Protected endpoints ───────────────────────────────────────────────

    @Override
    public ResponseEntity<VoidResponse> logout(UUID xUserId) {
        authService.logout(resolveUserId(xUserId));
        VoidResponse body = new VoidResponse();
        body.setSuccess(true);
        body.setMessage("Logged out");
        body.setTimestamp(OffsetDateTime.now());
        return ResponseEntity.ok(body);
    }

    @Override
    public ResponseEntity<UserInfoApiResponse> me(UUID xUserId, String xUserEmail, String xUserRoles) {
        String userId = resolveUserId(xUserId);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        UserInfoDto dto = new UserInfoDto();
        dto.setUserId(UUID.fromString(userId));
        dto.setEmail(xUserEmail != null ? xUserEmail : "");
        dto.setRoles(xUserRoles != null ? xUserRoles : rolesFromAuth(auth));

        UserInfoApiResponse body = new UserInfoApiResponse();
        body.setSuccess(true);
        body.setMessage("User info");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(dto);
        return ResponseEntity.ok(body);
    }

    // ── API Keys ──────────────────────────────────────────────────────────

    @Override
    public ResponseEntity<ApiKeyApiResponse> createApiKey(String name, UUID xUserId) {
        ApiKeyApiResponse body = new ApiKeyApiResponse();
        body.setSuccess(true);
        body.setMessage("API Key created — save this key, it won't be shown again");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(authService.createApiKey(resolveUserId(xUserId), name));
        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    @Override
    public ResponseEntity<ApiKeyListApiResponse> listApiKeys(UUID xUserId) {
        ApiKeyListApiResponse body = new ApiKeyListApiResponse();
        body.setSuccess(true);
        body.setMessage("API Keys");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(authService.listApiKeys(resolveUserId(xUserId)));
        return ResponseEntity.ok(body);
    }

    @Override
    public ResponseEntity<VoidResponse> revokeApiKey(UUID keyId, UUID xUserId) {
        authService.revokeApiKey(keyId.toString(), resolveUserId(xUserId));
        VoidResponse body = new VoidResponse();
        body.setSuccess(true);
        body.setMessage("API Key revoked");
        body.setTimestamp(OffsetDateTime.now());
        return ResponseEntity.ok(body);
    }

    /**
     * GET /auth/api-keys/{apiKey}
     *
     * The {apiKey} path parameter IS the raw key value.
     * ApiKeyAuthFilter already authenticated the request via the X-API-Key header.
     * We pass the raw key to the service which re-validates it and returns metadata.
     * rawKey is never included in the response.
     */
    @Override
    public ResponseEntity<ApiKeyApiResponse> validateApiKey(String apiKey) {
        ApiKeyApiResponse body = new ApiKeyApiResponse();
        body.setSuccess(true);
        body.setMessage("API Key is valid");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(authService.validateApiKey(apiKey));
        return ResponseEntity.ok(body);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Resolves the userId string using this priority:
     *   1. X-User-Id header (set by API Gateway in production)
     *   2. JWT/API-Key principal name (set by JwtAuthFilter / ApiKeyAuthFilter on direct calls)
     */
    private String resolveUserId(UUID xUserId) {
        if (xUserId != null) {
            return xUserId.toString();
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth.getName() != null
                && !"anonymousUser".equals(auth.getName())) {
            return auth.getName();
        }
        throw new AccessDeniedException("Not authenticated");
    }

    private String rolesFromAuth(Authentication auth) {
        if (auth == null) return "";
        return auth.getAuthorities().stream()
                .map(a -> a.getAuthority().replace("ROLE_", ""))
                .reduce((a, b) -> a + "," + b)
                .orElse("");
    }
}
