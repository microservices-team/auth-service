package com.diegoanyosa.authservice.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity @Table(name = "api_keys", schema = "auth")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ApiKey {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "key_hash", unique = true, nullable = false)
    private String keyHash;          // BCrypt hash — never store raw

    @Column(name = "key_prefix", length = 8)
    private String keyPrefix;        // First 8 chars shown to user: "da-abc12..."

    @Column(nullable = false)
    private String name;             // e.g. "frontend-prod"

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Builder.Default
    private boolean active = true;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }

    public boolean isValid() { return active && !isExpired(); }
}
