package com.diegoanyosa.authservice.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Reads the JWT from the "Authorization: Bearer <token>" header,
 * validates it, and populates the SecurityContext with the userId and roles.
 *
 * This is what allows protected endpoints like /api/auth/api-keys, /api/auth/me,
 * and /api/auth/logout to work when called directly (without an API Gateway).
 *
 * Flow:
 *   POST /api/auth/login  →  returns { accessToken, userId, ... }
 *   POST /api/auth/api-keys?name=x  +  Authorization: Bearer <accessToken>
 *                          →  JwtAuthFilter sets auth  →  X-User-Id read from JWT subject
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")
                && SecurityContextHolder.getContext().getAuthentication() == null) {

            String token = authHeader.substring(7);

            if (jwtService.isTokenValid(token)) {
                Claims claims = jwtService.extractClaims(token);

                String userId = claims.getSubject();                          // UUID stored as subject
                String roles  = claims.get("roles", String.class);           // "USER" or "USER,ADMIN"

                List<SimpleGrantedAuthority> authorities = roles != null
                        ? Arrays.stream(roles.split(","))
                                .map(String::trim)
                                .filter(r -> !r.isBlank())
                                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                                .toList()
                        : List.of();

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(userId, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(auth);
                log.debug("JWT authenticated userId={} roles={}", userId, roles);
            } else {
                log.warn("Invalid JWT from {}", request.getRemoteAddr());
            }
        }

        chain.doFilter(request, response);
    }
}
