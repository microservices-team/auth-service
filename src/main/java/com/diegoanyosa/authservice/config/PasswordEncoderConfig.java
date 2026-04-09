package com.diegoanyosa.authservice.config;

import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Separado de SecurityConfig para evitar ciclo de dependencia:
 * SecurityConfig → ApiKeyAuthFilter → PasswordEncoder → SecurityConfig
 */
@Configuration
@EnableDiscoveryClient
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
