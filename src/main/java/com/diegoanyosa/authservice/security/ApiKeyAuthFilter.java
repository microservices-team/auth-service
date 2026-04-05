package com.diegoanyosa.authservice.security;

import com.diegoanyosa.authservice.config.AppProperties;
import com.diegoanyosa.authservice.model.ApiKey;
import com.diegoanyosa.authservice.repository.ApiKeyRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private final ApiKeyRepository  apiKeyRepository;
    private final PasswordEncoder   passwordEncoder;
    private final AppProperties     appProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String headerName = appProperties.getApiKey().getHeaderName();
        String rawKey     = request.getHeader(headerName);

        if (rawKey != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Find candidate by prefix (first 8 chars) to avoid full table scan
            String prefix = rawKey.length() >= 8 ? rawKey.substring(0, 8) : rawKey;

            apiKeyRepository.findAll().stream()
                .filter(k -> k.isValid()
                    && prefix.equals(k.getKeyPrefix())
                    && passwordEncoder.matches(rawKey, k.getKeyHash()))
                .findFirst()
                .ifPresentOrElse(apiKey -> {
                    log.debug("API Key authenticated: {}", apiKey.getName());
                    var auth = new UsernamePasswordAuthenticationToken(
                        apiKey.getUser().getEmail(),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_API"))
                    );
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }, () -> log.warn("Invalid API Key from {}", request.getRemoteAddr()));
        }

        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only apply to non-OAuth2 paths
        String path = request.getRequestURI();
        return path.startsWith("/login/oauth2") || path.startsWith("/oauth2");
    }
}
