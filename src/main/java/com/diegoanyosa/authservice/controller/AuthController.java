package com.diegoanyosa.authservice.controller;

import com.diegoanyosa.authservice.dto.request.*;
import com.diegoanyosa.authservice.dto.response.*;
import com.diegoanyosa.authservice.service.AuthService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // ── JWT Auth ─────────────────────────────────────────────

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(ApiResponse.ok("Login successful", authService.login(request)));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(ApiResponse.ok("Registered", authService.register(request)));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(ApiResponse.ok("Token refreshed", authService.refresh(request)));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader("X-User-Id") String userId) {
        authService.logout(userId);
        return ResponseEntity.ok(ApiResponse.ok("Logged out", null));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserInfoResponse>> me(
            @RequestHeader("X-User-Id")    String userId,
            @RequestHeader("X-User-Email") String email,
            @RequestHeader("X-User-Roles") String roles) {
        return ResponseEntity.ok(ApiResponse.ok("User info",
            UserInfoResponse.builder().userId(userId).email(email).roles(roles).build()));
    }

    // ── OAuth2 callback info endpoint ─────────────────────────
    // Frontend lands here after OAuth2 redirect with token params

    @GetMapping("/oauth2/providers")
    public ResponseEntity<ApiResponse<List<String>>> providers() {
        return ResponseEntity.ok(ApiResponse.ok("Available providers",
            List.of("google", "github")));
    }

    // ── API Key management ────────────────────────────────────

    @PostMapping("/api-keys")
    public ResponseEntity<ApiResponse<ApiKeyResponse>> createApiKey(
            @RequestHeader("X-User-Id") String userId,
            @RequestParam @NotBlank String name) {
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(ApiResponse.ok("API Key created — save this key, it won't be shown again",
                authService.createApiKey(userId, name)));
    }

    @GetMapping("/api-keys")
    public ResponseEntity<ApiResponse<List<ApiKeyResponse>>> listApiKeys(
            @RequestHeader("X-User-Id") String userId) {
        return ResponseEntity.ok(ApiResponse.ok("API Keys", authService.listApiKeys(userId)));
    }

    @DeleteMapping("/api-keys/{keyId}")
    public ResponseEntity<ApiResponse<Void>> revokeApiKey(
            @PathVariable String keyId,
            @RequestHeader("X-User-Id") String userId) {
        authService.revokeApiKey(keyId, userId);
        return ResponseEntity.ok(ApiResponse.ok("API Key revoked", null));
    }
}
