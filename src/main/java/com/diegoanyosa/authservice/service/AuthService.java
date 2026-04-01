package com.diegoanyosa.authservice.service;

import com.diegoanyosa.authservice.dto.request.*;
import com.diegoanyosa.authservice.dto.response.AuthResponse;
import com.diegoanyosa.authservice.exception.AuthException;
import com.diegoanyosa.authservice.exception.UserAlreadyExistsException;
import com.diegoanyosa.authservice.model.*;
import com.diegoanyosa.authservice.repository.*;
import com.diegoanyosa.authservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository       userRepository;
    private final RoleRepository       roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService           jwtService;
    private final PasswordEncoder      passwordEncoder;

    @Value("${jwt.refresh-expiration-ms:604800000}")
    private long refreshExpirationMs;

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
            .orElseThrow(() -> new AuthException("Invalid credentials"));

        if (!user.isActive())
            throw new AuthException("Account is disabled");

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
            throw new AuthException("Invalid credentials");

        return buildAuthResponse(user);
    }

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

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {
        RefreshToken stored = refreshTokenRepository.findByToken(request.getRefreshToken())
            .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (!stored.isValid())
            throw new AuthException("Refresh token expired or revoked");

        // Rotate: revoke old, issue new
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        return buildAuthResponse(stored.getUser());
    }

    @Transactional
    public void logout(String userId) {
        userRepository.findById(UUID.fromString(userId))
            .ifPresent(refreshTokenRepository::revokeAllByUser);
        log.info("User logged out: {}", userId);
    }

    // ── Private helpers ──────────────────────────────────────

    private AuthResponse buildAuthResponse(User user) {
        Set<String> roleNames = user.getRoles().stream()
            .map(r -> r.getName().name())
            .collect(Collectors.toSet());

        String accessToken  = jwtService.generateToken(
            user.getId().toString(), user.getEmail(), roleNames);
        String refreshToken = generateRefreshToken(user);

        return AuthResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .tokenType("Bearer")
            .expiresIn(jwtService.getExpirationMs() / 1000)
            .userId(user.getId().toString())
            .email(user.getEmail())
            .name(user.getName())
            .roles(roleNames)
            .build();
    }

    private String generateRefreshToken(User user) {
        RefreshToken token = RefreshToken.builder()
            .user(user)
            .token(UUID.randomUUID().toString())
            .expiresAt(LocalDateTime.now().plusSeconds(refreshExpirationMs / 1000))
            .build();
        return refreshTokenRepository.save(token).getToken();
    }
}
