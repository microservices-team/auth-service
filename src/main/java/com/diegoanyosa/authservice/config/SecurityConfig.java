package com.diegoanyosa.authservice.config;

import com.diegoanyosa.authservice.security.*;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.rememberme.*;

import javax.sql.DataSource;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2SuccessHandler   oauth2SuccessHandler;
    private final UserDetailsServiceImpl userDetailsService;
    private final AppProperties          appProperties;
    private final DataSource             dataSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ApiKeyAuthFilter apiKeyAuthFilter) throws Exception {
        boolean oauth2Enabled = appProperties.getOauth2().isEnabled();
        log.info("OAuth2 login: {}", oauth2Enabled ? "ENABLED" : "DISABLED");

        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/auth/login",
                    "/api/auth/register",
                    "/api/auth/refresh",
                    "/api/auth/oauth2/providers",
                    "/actuator/health",
                    "/swagger-ui.html",
                    "/swagger-ui/**",
                    "/v3/api-docs",
                    "/v3/api-docs/**"
                ).permitAll()
                // Only allow oauth2 paths when enabled
                .requestMatchers("/login/oauth2/**", "/oauth2/**", "/api/auth/oauth2/**")
                    .access((authentication, context) -> {
                        if (!oauth2Enabled) {
                            return new org.springframework.security.authorization.AuthorizationDecision(false);
                        }
                        return new org.springframework.security.authorization.AuthorizationDecision(true);
                    })
                .anyRequest().authenticated()
            )
            .addFilterBefore(apiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .rememberMe(rm -> rm
                .tokenRepository(persistentTokenRepository())
                .userDetailsService(userDetailsService)
                .key(appProperties.getRememberMe().getKey())
                .tokenValiditySeconds(appProperties.getRememberMe().getTokenValiditySeconds())
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((req, res, authEx) -> {
                    res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"success\":false,\"message\":\"Unauthorized\"}");
                })
            );

        // Conditionally enable OAuth2 login
        if (oauth2Enabled) {
            http.oauth2Login(oauth2 -> oauth2
                .successHandler(oauth2SuccessHandler)
                .failureHandler((req, res, ex) ->
                    res.sendRedirect(appProperties.getApp().getOauth2().getFailureRedirect()))
            );
        } else {
            // Return 503 for oauth2 paths when disabled
            http.addFilterBefore((req, res, chain) -> {
                String path = ((jakarta.servlet.http.HttpServletRequest) req).getRequestURI();
                if (path.startsWith("/oauth2") || path.startsWith("/login/oauth2")) {
                    ((HttpServletResponse) res).setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                    (res).getWriter()
                        .write("{\"success\":false,\"message\":\"OAuth2 is temporarily disabled\"}");
                    return;
                }
                chain.doFilter(req, res);
            }, UsernamePasswordAuthenticationFilter.class);
        }

        return http.build();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        return repo;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
