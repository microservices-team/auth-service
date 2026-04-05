package com.diegoanyosa.authservice.service;

import com.diegoanyosa.authservice.config.AppProperties;
import com.diegoanyosa.authservice.dto.request.*;
import com.diegoanyosa.authservice.dto.response.*;
import com.diegoanyosa.authservice.exception.*;
import com.diegoanyosa.authservice.model.*;
import com.diegoanyosa.authservice.repository.*;
import com.diegoanyosa.authservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository         userRepository;
    private final RoleRepository         roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ApiKeyRepository       apiKeyRepository;
    private final JwtService             jwtService;
    private final PasswordEncoder        passwordEncoder;
    private final AppProperties          appProperties;

    // ── Login with Account Lockout ───────────────────────────

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
            .orElseThrow(() -> new AuthException("Invalid credentials"));

        if (!user.isActive())
            throw new AuthException("Account is disabled");

        // Check lockout
        if (user.isLocked()) {
            throw new AccountLockedException(
                "Account locked until " + user.getLockedUntil()
                    + ". Too many failed attempts.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            handleFailedAttempt(user);
            throw new AuthException("Invalid credentials");
        }

        // Success — reset counter
        user.resetFailedAttempts();
        userRepository.save(user);

        return buildAuthResponse(user);
    }

    private void handleFailedAttempt(User user) {
        user.incrementFailedAttempts();
        int maxAttempts = appProperties.getAccount().getMaxFailedAttempts();

        if (user.getFailedAttempts() >= maxAttempts) {
            int lockMinutes = appProperties.getAccount().getLockoutDurationMinutes();
            user.setLockedUntil(LocalDateTime.now().plusMinutes(lockMinutes));
            log.warn("Account locked: {} after {} failed attempts", user.getEmail(), maxAttempts);
        }
        userRepository.save(user);
    }

    // ── Register ─────────────────────────────────────────────

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail()))
            throw new UserAlreadyExistsException(request.getEmail());

        Role userRole = roleRepository.findByName(Role.RoleName.USER)
            .orElseThrow(() -> new RuntimeException("Role USER not found"));

        User user = User.builder()
            .email(request.getEmail())
            .passwordHash(passwordEncoder.encode(request.getPassword()))
            .name(request.getName())
            .roles(Set.of(userRole))
            .build();

        userRepository.save(user);
        log.info("New user registered: {}", user.getEmail());
        return buildAuthResponse(user);
    }

    // ── Refresh Token ─────────────────────────────────────────

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {
        RefreshToken stored = refreshTokenRepository.findByToken(request.getRefreshToken())
            .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (!stored.isValid())
            throw new AuthException("Refresh token expired or revoked");

        stored.setRevoked(true);
        refreshTokenRepository.save(stored);
        return buildAuthResponse(stored.getUser());
    }

    // ── Logout ───────────────────────────────────────────────

    @Transactional
    public void logout(String userId) {
        userRepository.findById(UUID.fromString(userId))
            .ifPresent(refreshTokenRepository::revokeAllByUser);
        log.info("User logged out: {}", userId);
    }

    // ── API Key management ────────────────────────────────────

    @Transactional
    public ApiKeyResponse createApiKey(String userId, String keyName) {
        User user = userRepository.findById(UUID.fromString(userId))
            .orElseThrow(() -> new AuthException("User not found"));

        // Generate raw key: "da-" + UUID without dashes
        String rawKey = "da-" + UUID.randomUUID().toString().replace("-", "");
        String prefix = rawKey.substring(0, 8);
        String hash   = passwordEncoder.encode(rawKey);

        ApiKey apiKey = ApiKey.builder()
            .user(user).name(keyName)
            .keyHash(hash).keyPrefix(prefix)
            .build();

        apiKeyRepository.save(apiKey);
        log.info("API Key created: {} for user {}", keyName, user.getEmail());

        // Return raw key ONCE — never stored
        return ApiKeyResponse.builder()
            .id(apiKey.getId().toString())
            .name(keyName)
            .prefix(prefix)
            .rawKey(rawKey)  // shown only once
            .createdAt(apiKey.getCreatedAt())
            .build();
    }

    @Transactional
    public void revokeApiKey(String keyId, String userId) {
        ApiKey key = apiKeyRepository.findById(UUID.fromString(keyId))
            .orElseThrow(() -> new AuthException("API Key not found"));

        if (!key.getUser().getId().toString().equals(userId))
            throw new AuthException("Not authorized to revoke this key");

        key.setActive(false);
        apiKeyRepository.save(key);
    }

    public List<ApiKeyResponse> listApiKeys(String userId) {
        User user = userRepository.findById(UUID.fromString(userId))
            .orElseThrow(() -> new AuthException("User not found"));

        return apiKeyRepository.findByUserAndActiveTrue(user).stream()
            .map(k -> ApiKeyResponse.builder()
                .id(k.getId().toString())
                .name(k.getName())
                .prefix(k.getKeyPrefix())
                .createdAt(k.getCreatedAt())
                .build())
            .toList();
    }

    // ── Helpers ──────────────────────────────────────────────

    private AuthResponse buildAuthResponse(User user) {
        Set<String> roleNames = user.getRoles().stream()
            .map(r -> r.getName().name()).collect(Collectors.toSet());

        String accessToken  = jwtService.generateToken(
            user.getId().toString(), user.getEmail(), roleNames);
        String refreshToken = generateRefreshToken(user);

        return AuthResponse.builder()
            .accessToken(accessToken).refreshToken(refreshToken)
            .tokenType("Bearer").expiresIn(jwtService.getExpirationMs() / 1000)
            .userId(user.getId().toString()).email(user.getEmail())
            .name(user.getName()).roles(roleNames).build();
    }

    private String generateRefreshToken(User user) {
        RefreshToken token = RefreshToken.builder()
            .user(user).token(UUID.randomUUID().toString())
            .expiresAt(LocalDateTime.now().plusSeconds(
                appProperties.getRememberMe().getTokenValiditySeconds()))
            .build();
        return refreshTokenRepository.save(token).getToken();
    }
}
