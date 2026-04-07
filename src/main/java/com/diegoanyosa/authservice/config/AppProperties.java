package com.diegoanyosa.authservice.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.stereotype.Component;

@Data
@Component
@EnableDiscoveryClient
@ConfigurationProperties(prefix = "security")
public class AppProperties {

    private Account  account    = new Account();
    private RememberMe rememberMe = new RememberMe();
    private ApiKey   apiKey     = new ApiKey();
    private App      app        = new App();
    private OAuth2   oauth2     = new OAuth2();

    @Data
    public static class Account {
        private int maxFailedAttempts     = 3;
        private int lockoutDurationMinutes = 30;
    }

    @Data
    public static class RememberMe {
        private String key                  = "da-remember-me-secret";
        private int    tokenValiditySeconds = 604800;
    }

    @Data
    public static class ApiKey {
        private String headerName = "X-API-Key";
    }

    @Data
    public static class App {
        private String  frontendUrl = "http://localhost:5173";
        private OAuth2Config oauth2 = new OAuth2Config();

        @Data
        public static class OAuth2Config {
            private String successRedirect = "http://localhost:5173/oauth2/callback";
            private String failureRedirect = "http://localhost:5173/login?error=oauth2";
        }
    }

    /**
     * Feature flags for OAuth2.
     * Disable temporarily with: security.oauth2.enabled=false in config YAML.
     * When disabled, /oauth2/** and /login/oauth2/** return 503.
     */
    @Data
    public static class OAuth2 {
        private boolean enabled = true;
    }
}
