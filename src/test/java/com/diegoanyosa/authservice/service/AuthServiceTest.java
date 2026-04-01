package com.diegoanyosa.authservice.service;

import com.diegoanyosa.authservice.dto.request.*;
import com.diegoanyosa.authservice.dto.response.AuthResponse;
import com.diegoanyosa.authservice.exception.*;
import com.diegoanyosa.authservice.model.*;
import com.diegoanyosa.authservice.repository.*;
import com.diegoanyosa.authservice.security.JwtService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository        userRepository;
    @Mock private RoleRepository        roleRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private JwtService            jwtService;
    @Mock private PasswordEncoder       passwordEncoder;

    @InjectMocks
    private AuthService authService;

    private User testUser;
    private Role userRole;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "refreshExpirationMs", 604800000L);

        userRole = Role.builder()
            .id(UUID.randomUUID())
            .name(Role.RoleName.USER)
            .build();

        testUser = User.builder()
            .id(UUID.randomUUID())
            .email("diego@diegoanyosa.com")
            .passwordHash("$2a$12$hashedpassword")
            .name("Diego Anyosa")
            .active(true)
            .roles(Set.of(userRole))
            .build();
    }

    @Test
    @DisplayName("Login succeeds with valid credentials")
    void login_ValidCredentials_ReturnsAuthResponse() {
        LoginRequest req = new LoginRequest();
        req.setEmail("diego@diegoanyosa.com");
        req.setPassword("password123");

        when(userRepository.findByEmail(req.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(req.getPassword(), testUser.getPasswordHash())).thenReturn(true);
        when(jwtService.generateToken(anyString(), anyString(), anySet())).thenReturn("jwt-token");
        when(jwtService.getExpirationMs()).thenReturn(3600000L);
        when(refreshTokenRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        AuthResponse response = authService.login(req);

        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("jwt-token");
        assertThat(response.getEmail()).isEqualTo(testUser.getEmail());
        assertThat(response.getRoles()).contains("USER");
    }

    @Test
    @DisplayName("Login fails with wrong password")
    void login_WrongPassword_ThrowsAuthException() {
        LoginRequest req = new LoginRequest();
        req.setEmail("diego@diegoanyosa.com");
        req.setPassword("wrongpassword");

        when(userRepository.findByEmail(req.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(req.getPassword(), testUser.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(req))
            .isInstanceOf(AuthException.class)
            .hasMessage("Invalid credentials");
    }

    @Test
    @DisplayName("Login fails for nonexistent user")
    void login_UserNotFound_ThrowsAuthException() {
        LoginRequest req = new LoginRequest();
        req.setEmail("unknown@test.com");
        req.setPassword("password");

        when(userRepository.findByEmail(req.getEmail())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(req))
            .isInstanceOf(AuthException.class);
    }

    @Test
    @DisplayName("Register succeeds with new email")
    void register_NewEmail_ReturnsAuthResponse() {
        RegisterRequest req = new RegisterRequest();
        req.setName("Diego Anyosa");
        req.setEmail("new@diegoanyosa.com");
        req.setPassword("password123");

        when(userRepository.existsByEmail(req.getEmail())).thenReturn(false);
        when(roleRepository.findByName(Role.RoleName.USER)).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode(req.getPassword())).thenReturn("$2a$12$encoded");
        when(userRepository.save(any())).thenReturn(testUser);
        when(jwtService.generateToken(anyString(), anyString(), anySet())).thenReturn("jwt-token");
        when(jwtService.getExpirationMs()).thenReturn(3600000L);
        when(refreshTokenRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        AuthResponse response = authService.register(req);

        assertThat(response).isNotNull();
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Register fails when email already exists")
    void register_DuplicateEmail_ThrowsException() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("existing@test.com");
        req.setPassword("password");
        req.setName("Test");

        when(userRepository.existsByEmail(req.getEmail())).thenReturn(true);

        assertThatThrownBy(() -> authService.register(req))
            .isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    @DisplayName("Refresh succeeds with valid token")
    void refresh_ValidToken_ReturnsNewTokens() {
        RefreshToken token = RefreshToken.builder()
            .id(UUID.randomUUID())
            .user(testUser)
            .token("valid-refresh-token")
            .expiresAt(LocalDateTime.now().plusDays(7))
            .revoked(false)
            .build();

        RefreshTokenRequest req = new RefreshTokenRequest();
        req.setRefreshToken("valid-refresh-token");

        when(refreshTokenRepository.findByToken("valid-refresh-token")).thenReturn(Optional.of(token));
        when(refreshTokenRepository.save(any())).thenAnswer(i -> i.getArgument(0));
        when(jwtService.generateToken(anyString(), anyString(), anySet())).thenReturn("new-jwt-token");
        when(jwtService.getExpirationMs()).thenReturn(3600000L);

        AuthResponse response = authService.refresh(req);

        assertThat(response.getAccessToken()).isEqualTo("new-jwt-token");
        assertThat(token.isRevoked()).isTrue(); // old token revoked
    }
}
