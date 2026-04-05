package com.diegoanyosa.authservice.security;

import com.diegoanyosa.authservice.config.AppProperties;
import com.diegoanyosa.authservice.model.*;
import com.diegoanyosa.authservice.repository.*;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository         userRepository;
    private final RoleRepository         roleRepository;
    private final OAuthProviderRepository oauthProviderRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService             jwtService;
    private final AppProperties          appProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
            HttpServletResponse response, Authentication authentication)
            throws IOException {

        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();

        // Extract provider info from the registration ID in the request path
        String registrationId = extractRegistrationId(request);
        String providerUserId = resolveProviderId(oauthUser, registrationId);
        String email          = resolveEmail(oauthUser, registrationId);
        String name           = oauthUser.getAttribute("name") != null
                                ? oauthUser.getAttribute("name") : email;

        // Find or create user
        User user = oauthProviderRepository
            .findByProviderAndProviderUserId(registrationId, providerUserId)
            .map(OAuthProvider::getUser)
            .orElseGet(() -> createOAuthUser(email, name, registrationId, providerUserId, email));

        // Generate JWT
        Set<String> roles = new HashSet<>();
        user.getRoles().forEach(r -> roles.add(r.getName().name()));

        String accessToken  = jwtService.generateToken(user.getId().toString(), user.getEmail(), roles);
        String refreshToken = createRefreshToken(user);

        // Redirect to frontend with tokens
        String redirectUrl = UriComponentsBuilder
            .fromUriString(appProperties.getApp().getOauth2().getSuccessRedirect())
            .queryParam("token",         accessToken)
            .queryParam("refreshToken",  refreshToken)
            .queryParam("provider",      registrationId)
            .build().toUriString();

        log.info("OAuth2 login success: {} via {}", email, registrationId);
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    private User createOAuthUser(String email, String name,
            String provider, String providerUserId, String providerEmail) {

        Role userRole = roleRepository.findByName(Role.RoleName.USER)
            .orElseThrow(() -> new RuntimeException("Role USER not found"));

        // If email already registered, link the provider
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = User.builder()
                .email(email).name(name)
                .passwordHash("{noop}oauth2-no-password")
                .roles(Set.of(userRole)).active(true)
                .build();
            return userRepository.save(newUser);
        });

        OAuthProvider link = OAuthProvider.builder()
            .user(user).provider(provider)
            .providerUserId(providerUserId)
            .providerEmail(providerEmail)
            .build();
        oauthProviderRepository.save(link);

        return user;
    }

    private String createRefreshToken(User user) {
        RefreshToken token = RefreshToken.builder()
            .user(user).token(UUID.randomUUID().toString())
            .expiresAt(LocalDateTime.now().plusDays(7)).build();
        return refreshTokenRepository.save(token).getToken();
    }

    private String extractRegistrationId(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri.contains("google")) return "google";
        if (uri.contains("github")) return "github";
        return "unknown";
    }

    private String resolveProviderId(OAuth2User user, String provider) {
        if ("github".equals(provider)) {
            Object id = user.getAttribute("id");
            return id != null ? id.toString() : user.getName();
        }
        return user.getName(); // Google sub
    }

    private String resolveEmail(OAuth2User user, String provider) {
        String email = user.getAttribute("email");
        if (email == null && "github".equals(provider)) {
            // GitHub may not expose email; use login as fallback
            String login = user.getAttribute("login");
            email = login + "@github.noemail";
        }
        return email != null ? email : user.getName() + "@oauth.noemail";
    }
}
