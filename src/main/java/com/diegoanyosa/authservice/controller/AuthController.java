package com.diegoanyosa.authservice.controller;

import com.diegoanyosa.authservice.dto.request.*;
import com.diegoanyosa.authservice.dto.response.*;
import com.diegoanyosa.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request) {
        AuthResponse auth = authService.login(request);
        return ResponseEntity.ok(ApiResponse.ok("Login successful", auth));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        AuthResponse auth = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(ApiResponse.ok("Registration successful", auth));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse auth = authService.refresh(request);
        return ResponseEntity.ok(ApiResponse.ok("Token refreshed", auth));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader("X-User-Id") String userId) {
        authService.logout(userId);
        return ResponseEntity.ok(ApiResponse.ok("Logged out successfully", null));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserInfoResponse>> me(
            @RequestHeader("X-User-Id")    String userId,
            @RequestHeader("X-User-Email") String email,
            @RequestHeader("X-User-Roles") String roles) {
        UserInfoResponse info = UserInfoResponse.builder()
            .userId(userId).email(email).roles(roles).build();
        return ResponseEntity.ok(ApiResponse.ok("User info", info));
    }
}
