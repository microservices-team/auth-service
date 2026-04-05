package com.diegoanyosa.authservice.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity @Table(name = "oauth_providers", schema = "auth",
    uniqueConstraints = @UniqueConstraint(columnNames = {"provider", "provider_user_id"}))
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class OAuthProvider {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 30)
    private String provider;           // "google" | "github"

    @Column(name = "provider_user_id", nullable = false)
    private String providerUserId;     // ID from the provider

    @Column(name = "provider_email")
    private String providerEmail;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
}
