package com.diegoanyosa.authservice.service;

import com.diegoanyosa.authservice.config.AppProperties;
import com.diegoanyosa.authservice.exception.*;
import com.diegoanyosa.authservice.model.*;
import com.diegoanyosa.authservice.model.*;
import com.diegoanyosa.authservice.repository.*;
import com.diegoanyosa.authservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Business logic layer.
 * All method signatures use DTOs from the generated package
 * (com.diegoanyosa.authservice.generated.model.*) produced from auth-api.yaml.
 */
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

    // ── Login ─────────────────────────────────────────────────────────────

    @Transactional
    public AuthDto login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AuthException("Invalid credentials"));

        if (!user.isActive())
            throw new AuthException("Account is disabled");

        if (user.isLocked())
            throw new AccountLockedException(
                    "Account locked until " + user.getLockedUntil() + ". Too many failed attempts.");

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            handleFailedAttempt(user);
            throw new AuthException("Invalid credentials");
        }

        user.resetFailedAttempts();
        userRepository.save(user);
        return buildAuthDto(user);
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

    // ── Register ──────────────────────────────────────────────────────────

    @Transactional
    public AuthDto register(RegisterRequest request) {
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

        var savedUser = userRepository.save(user);
        log.info("New user registered: {}", user.getEmail());
        return buildAuthDto(savedUser);
    }

    // ── Refresh ───────────────────────────────────────────────────────────

    @Transactional
    public AuthDto refresh(RefreshTokenRequest request) {
        RefreshToken stored = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (!stored.isValid())
            throw new AuthException("Refresh token expired or revoked");

        stored.setRevoked(true);
        refreshTokenRepository.save(stored);
        return buildAuthDto(stored.getUser());
    }

    // ── Logout ────────────────────────────────────────────────────────────

    @Transactional
    public void logout(String userId) {
        userRepository.findById(UUID.fromString(userId))
                .ifPresent(refreshTokenRepository::revokeAllByUser);
        log.info("User logged out: {}", userId);
    }

    // ── API Keys ──────────────────────────────────────────────────────────

    @Transactional
    public ApiKeyDto createApiKey(String userId, String keyName) {
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new AuthException("User not found"));

        String rawKey = "da-" + UUID.randomUUID().toString().replace("-", "");
        String prefix = rawKey.substring(0, 8);
        String hash   = passwordEncoder.encode(rawKey);

        ApiKey apiKey = ApiKey.builder()
                .user(user).name(keyName)
                .keyHash(hash).keyPrefix(prefix)
                .build();

        apiKeyRepository.save(apiKey);
        log.info("API Key created: {} for user {}", keyName, user.getEmail());

        ApiKeyDto dto = new ApiKeyDto();
        dto.setId(UUID.fromString(apiKey.getId().toString()));
        dto.setName(keyName);
        dto.setPrefix(prefix);
        dto.setRawKey(rawKey);
        dto.setCreatedAt(apiKey.getCreatedAt() != null
                ? apiKey.getCreatedAt().atOffset(java.time.ZoneOffset.UTC) : OffsetDateTime.now());
        return dto;
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

    public List<ApiKeyDto> listApiKeys(String userId) {
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new AuthException("User not found"));

        return apiKeyRepository.findByUserAndActiveTrue(user).stream()
                .map(k -> {
                    ApiKeyDto dto = new ApiKeyDto();
                    dto.setId(UUID.fromString(k.getId().toString()));
                    dto.setName(k.getName());
                    dto.setPrefix(k.getKeyPrefix());
                    dto.setCreatedAt(k.getCreatedAt() != null
                            ? k.getCreatedAt().atOffset(java.time.ZoneOffset.UTC) : OffsetDateTime.now());
                    return dto;
                })
                .toList();
    }

    public ApiKeyDto validateApiKey(String rawKey) {
        if (rawKey == null || rawKey.isBlank()) {
            throw new AuthException("API Key value is required");
        }

        // Use the prefix (first 8 chars) to narrow candidates, then BCrypt-verify
        String prefix = rawKey.length() >= 8 ? rawKey.substring(0, 8) : rawKey;

        ApiKey key = apiKeyRepository.findByKeyPrefixAndActiveTrue(prefix).stream()
                .filter(k -> passwordEncoder.matches(rawKey, k.getKeyHash()))
                .findFirst()
                .orElseThrow(() -> new AuthException("API Key not found or inactive"));

        ApiKeyDto dto = new ApiKeyDto();
        dto.setId(key.getId());
        dto.setName(key.getName());
        dto.setPrefix(key.getKeyPrefix());
        // rawKey is intentionally NOT set — never stored, only returned at creation
        dto.setCreatedAt(key.getCreatedAt() != null
                ? key.getCreatedAt().atOffset(java.time.ZoneOffset.UTC) : OffsetDateTime.now());
        return dto;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private AuthDto buildAuthDto(User user) {
        Set<String> roleNames = user.getRoles().stream()
                .map(r -> r.getName().name()).collect(Collectors.toSet());

        String accessToken  = jwtService.generateToken(
                user.getId().toString(), user.getEmail(), roleNames);
        String refreshToken = generateRefreshToken(user);

        AuthDto dto = new AuthDto();
        dto.setAccessToken(accessToken);
        dto.setRefreshToken(refreshToken);
        dto.setTokenType("Bearer");
        dto.setExpiresIn(jwtService.getExpirationMs() / 1000);
        dto.setUserId(UUID.fromString(user.getId().toString()));
        dto.setEmail(user.getEmail());
        dto.setName(user.getName());
        dto.setRoles(new ArrayList<>(roleNames));
        return dto;
    }

    private String generateRefreshToken(User user) {
        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiresAt(LocalDateTime.now().plusSeconds(
                        appProperties.getRememberMe().getTokenValiditySeconds()))
                .build();
        return refreshTokenRepository.save(token).getToken();
    }
}
