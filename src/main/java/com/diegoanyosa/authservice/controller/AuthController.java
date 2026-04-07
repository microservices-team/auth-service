package com.diegoanyosa.authservice.controller;

import com.diegoanyosa.authservice.api.AuthApiDelegate;
import com.diegoanyosa.authservice.api.model.*;
import com.diegoanyosa.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Implements the generated {@link AuthApiDelegate}.
 *
 * The openapi-generator-maven-plugin reads auth-api.yaml and produces:
 *   AuthApi           – the @RequestMapping interface (wired by Spring MVC)
 *   AuthApiDelegate   – the delegate interface implemented here
 *   model/            – all request/response DTOs
 *
 * No security annotations needed here: public vs protected access is
 * enforced by SecurityConfig (URL-level) and the ApiKeyAuthFilter.
 */
@Component
@RequiredArgsConstructor
public class AuthController implements AuthApiDelegate {

    private final AuthService authService;

    // ── JWT Auth ──────────────────────────────────────────────────────────

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
    public ResponseEntity<VoidResponse> logout(UUID xUserId) {
        authService.logout(xUserId.toString());
        VoidResponse body = new VoidResponse();
        body.setSuccess(true);
        body.setMessage("Logged out");
        body.setTimestamp(OffsetDateTime.now());
        return ResponseEntity.ok(body);
    }

    @Override
    public ResponseEntity<UserInfoApiResponse> me(UUID xUserId, String xUserEmail, String xUserRoles) {
        UserInfoDto dto = new UserInfoDto();
        dto.setUserId(UUID.fromString(xUserId.toString()));
        dto.setEmail(xUserEmail);
        dto.setRoles(xUserRoles);

        UserInfoApiResponse body = new UserInfoApiResponse();
        body.setSuccess(true);
        body.setMessage("User info");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(dto);
        return ResponseEntity.ok(body);
    }

    // ── OAuth2 ────────────────────────────────────────────────────────────

    @Override
    public ResponseEntity<ProvidersApiResponse> getOAuth2Providers() {
        ProvidersApiResponse body = new ProvidersApiResponse();
        body.setSuccess(true);
        body.setMessage("Available providers");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(List.of("google", "github"));
        return ResponseEntity.ok(body);
    }

    // ── API Keys ──────────────────────────────────────────────────────────

    @Override
    public ResponseEntity<ApiKeyApiResponse> createApiKey(UUID xUserId, String name) {
        ApiKeyApiResponse body = new ApiKeyApiResponse();
        body.setSuccess(true);
        body.setMessage("API Key created — save this key, it won't be shown again");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(authService.createApiKey(xUserId.toString(), name));
        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    @Override
    public ResponseEntity<ApiKeyListApiResponse> listApiKeys(UUID xUserId) {
        ApiKeyListApiResponse body = new ApiKeyListApiResponse();
        body.setSuccess(true);
        body.setMessage("API Keys");
        body.setTimestamp(OffsetDateTime.now());
        body.setData(authService.listApiKeys(xUserId.toString()));
        return ResponseEntity.ok(body);
    }

    @Override
    public ResponseEntity<VoidResponse> revokeApiKey(UUID keyId, UUID xUserId) {
        authService.revokeApiKey(keyId.toString(), xUserId.toString());
        VoidResponse body = new VoidResponse();
        body.setSuccess(true);
        body.setMessage("API Key revoked");
        body.setTimestamp(OffsetDateTime.now());
        return ResponseEntity.ok(body);
    }
}
