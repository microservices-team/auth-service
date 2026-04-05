package com.diegoanyosa.authservice.config;

import com.diegoanyosa.authservice.security.*;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2SuccessHandler  oauth2SuccessHandler;
    private final UserDetailsServiceImpl userDetailsService;
    private final AppProperties         appProperties;
    private final DataSource            dataSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ApiKeyAuthFilter apiKeyAuthFilter) throws Exception {
        return http
            .csrf(AbstractHttpConfigurer::disable)

            // Stateless for API endpoints
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/auth/login",
                    "/api/auth/register",
                    "/api/auth/refresh",
                    "/api/auth/oauth2/**",
                    "/login/oauth2/**",
                    "/oauth2/**",
                    "/actuator/health"
                ).permitAll()
                .anyRequest().authenticated()
            )

            // API Key filter — runs before UsernamePassword filter
            .addFilterBefore(apiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class)

            // OAuth2 Login
//            .oauth2Login(oauth2 -> oauth2
//                .successHandler(oauth2SuccessHandler)
//                .failureHandler((req, res, ex) -> {
//                    res.sendRedirect(appProperties.getApp().getOauth2().getFailureRedirect());
//                })
//            )

            // Remember Me — persisted in PostgreSQL
            .rememberMe(rm -> rm
                .tokenRepository(persistentTokenRepository())
                .userDetailsService(userDetailsService)
                .key(appProperties.getRememberMe().getKey())
                .tokenValiditySeconds(appProperties.getRememberMe().getTokenValiditySeconds())
            )

            // Unauthorized handler — return JSON, not redirect
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((req, res, authEx) -> {
                    res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"success\":false,\"message\":\"Unauthorized\"}");
                })
            )
            .build();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        return repo;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
